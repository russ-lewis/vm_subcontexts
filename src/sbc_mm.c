#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include "vm_sbc.h"

/* Global state for mapped subcontexts and client executable regions.  These
 * are used by the permission switching code in the segfault handler. */
MappedSubcontext mapped_subcontexts[MAX_IMG_FILES];
size_t          num_mapped_subcontexts = 0;
ClientRegion    client_regions[MAX_ENTRIES];
size_t          num_client_regions = 0;
static int      segv_handler_installed = 0;
static int      mm_initialized = 0;

/* Forward declarations */
static void segv_handler(int sig, siginfo_t *info, void *context);

/* Initialize the client library and install the segfault handler
 * (i.e., the Matchmaker) automatically
 */
void sbc_client_init() {
    printf("Initializing SBC client...\n");
    memset(mapped_subcontexts, 0, sizeof(mapped_subcontexts));
    memset(client_regions, 0, sizeof(client_regions));
    num_mapped_subcontexts = 0;
    num_client_regions = 0;

    if (record_client_memory_regions() != 0) {
        fprintf(stderr, "Warning: Failed to record client memory regions\n");
    }

    if (setup_segv_handler() != 0) {
        fprintf(stderr, "Error: Failed to set up segmentation fault handler\n");
        exit(EXIT_FAILURE);
    }
    printf("SBC client initialized successfully\n");
}

/* Matchmaker initialization */
void init() {
    if (!mm_initialized) {
        sbc_client_init();
        mm_initialized = 1;
    }
}

/* Request mapping of a server image */
int request_map(const char *img_fname) {
    if (!mm_initialized) {
        init();
    }
    return map_subcontext(img_fname);
}

/* these functions help to manage permissions */
int record_client_memory_regions(void) {
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        perror("Error opening /proc/self/maps");
        return -1;
    }

    char line[256];
    num_client_regions = 0;
    while (fgets(line, sizeof(line), maps_file) != NULL &&
           num_client_regions < MAX_ENTRIES) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (perms[2] == 'x') {
                /* when enabling or disabling executable permissions, we skip [vdso]
                 * and [vsyscall] to avoid errors. specifically, changing
                 * the permissions of these regions with mprotect results
                 * in ENOMEM errors
                 */
                if (strstr(line, "[vdso]") || strstr(line, "[vvar]") ||
                    strstr(line, "[vsyscall]")) {
                    continue;
                }

                client_regions[num_client_regions].start = (void *)start;
                client_regions[num_client_regions].end   = (void *)end;
                client_regions[num_client_regions].original_prot =
                    perms_to_prot(perms);
                num_client_regions++;
            }
        }
    }
    fclose(maps_file);
    printf("Recorded %zu client executable regions\n", num_client_regions);
    return 0;
}

int disable_client_execute_permissions(void) {
    for (size_t i = 0; i < num_client_regions; i++) {
        ClientRegion *region = &client_regions[i];
        if (is_library_address(region->start))
            continue;
        size_t size = (char*)region->end - (char*)region->start;
        int new_prot = region->original_prot & ~PROT_EXEC;
        if (mprotect(region->start, size, new_prot) == -1) {
            perror("Error disabling client execute permissions");
            return -1;
        }
    }
    return 0;
}

int enable_client_execute_permissions(void) {
    for (size_t i = 0; i < num_client_regions; i++) {
        ClientRegion *region = &client_regions[i];
        if (is_library_address(region->start))
            continue;
        size_t size = (char*)region->end - (char*)region->start;
        if (mprotect(region->start, size, region->original_prot) == -1) {
            perror("Error re-enabling client execute permissions");
            return -1;
        }
    }
    return 0;
}

int enable_subcontext_execute_permissions(void *fault_addr) {
    MappedSubcontext *subctx = find_subcontext_by_addr(fault_addr);
    if (!subctx)
        return -1;
    for (size_t i = 0; i < subctx->num_entries; i++) {
        Entry *entry = &subctx->entries[i];
        size_t region_size = entry->end - entry->start;
        int prot = perms_to_prot(entry->perms);
        if (mprotect((void*)entry->start, region_size, prot) == -1) {
            perror("Error enabling subcontext permissions");
            return -1;
        }
    }
    subctx->is_active = 1;
    return 0;
}

int disable_all_subcontext_execute_permissions(void) {
    for (size_t i = 0; i < num_mapped_subcontexts; i++) {
        MappedSubcontext *subctx = &mapped_subcontexts[i];
        for (size_t j = 0; j < subctx->num_entries; j++) {
            Entry *entry = &subctx->entries[j];
            size_t region_size = entry->end - entry->start;
            if (mprotect((void*)entry->start, region_size, PROT_READ | PROT_WRITE) == -1) {
                perror("Error disabling subcontext permissions");
                return -1;
            }
        }
        subctx->is_active = 0;
    }
    return 0;
}

MappedSubcontext* find_subcontext_by_addr(void *addr) {
    for (size_t i = 0; i < num_mapped_subcontexts; i++) {
        MappedSubcontext *subctx = &mapped_subcontexts[i];
        for (size_t j = 0; j < subctx->num_entries; j++) {
            Entry *entry = &subctx->entries[j];
            if ((unsigned long)addr >= entry->start && (unsigned long)addr < entry->end)
                return subctx;
        }
    }
    return NULL;
}

int is_library_address(void *addr) {
    // TODO: cache this
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file)
        return 0;
    char line[256];
    int is_lib = 0;
    while (fgets(line, sizeof(line), maps_file) != NULL) {
        unsigned long start, end;
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if ((unsigned long)addr >= start && (unsigned long)addr < end) {
                if (strstr(line, ".so") || strstr(line, "libc") ||
                    strstr(line, "ld-") || strstr(line, "[vdso]") ||
                    strstr(line, "[vvar]") || strstr(line, "[vsyscall]")) {
                    is_lib = 1;
                }
                break;
            }
        }
    }
    fclose(maps_file);
    return is_lib;
}

/* the actual segmentation fault handler */
static void segv_handler(int sig, siginfo_t *info, void *context) {
    void *fault_addr = info->si_addr;
    printf("SEGV handler triggered at address: %p\n", fault_addr);
    mm_handle_segv(fault_addr);

    /* if the address does not belong to any mapped subcontext, this handler
     * cannot resolve the fault so we re-raise SIGSEGV with the default so
     * that the process does not endlessly loop in the handler.
     */
    if (!find_subcontext_by_addr(fault_addr)) {
        struct sigaction sa = {0};
        sa.sa_handler = SIG_DFL;
        sigaction(SIGSEGV, &sa, NULL);
        raise(SIGSEGV);
    }
}

int setup_segv_handler(void) {
    if (segv_handler_installed)
        return 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = segv_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) == -1) {
        perror("Error installing SIGSEGV handler");
        return -1;
    }
    segv_handler_installed = 1;
    printf("SIGSEGV handler installed successfully\n");
    return 0;
}

/* logic for permission switching--used by the SEGV handler */
void mm_handle_segv(void *fault_addr) {
    if (is_library_address(fault_addr))
        return;
    MappedSubcontext *target_subctx = find_subcontext_by_addr(fault_addr);
    if (target_subctx) {
        disable_client_execute_permissions();
        disable_all_subcontext_execute_permissions();
        enable_subcontext_execute_permissions(fault_addr);
    } else {
        disable_all_subcontext_execute_permissions();
        enable_client_execute_permissions();
    }
}

/* Finalize matchmaker */
void finalize() {
    disable_all_subcontext_execute_permissions();
    enable_client_execute_permissions();
}

