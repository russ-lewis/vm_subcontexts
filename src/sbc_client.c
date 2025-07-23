#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>
#include "vm_sbc.h"

/*
 * The matchmaker (sbc_mm.c) maintains the global state for mapped
 * subcontexts and the segfault handler.  This file only implements the
 * routines required to map a subcontext image and to call functions in
 * that image.
 */

/* extern globals defined in sbc_mm.c */
extern MappedSubcontext mapped_subcontexts[MAX_IMG_FILES];
extern size_t          num_mapped_subcontexts;

/* Map a server image into the client's address space. The mapped
 * regions are initially given read/write permissions only.  Execute
 * permissions are managed by the matchmaker's segfault handler.
 */
int map_subcontext(const char *img_file) {
    printf("Mapping subcontext from file: %s\n", img_file);

    // error check number of mapped subcontexts
    if (num_mapped_subcontexts >= MAX_IMG_FILES) {
        fprintf(stderr, "Error: Maximum number of subcontexts already mapped\n");
        return EXIT_FAILURE;
    }

    // open the image file that we want to map
    int fd = open(img_file, O_RDWR);
    if (fd == -1) {
        perror("Error opening image file");
        return EXIT_FAILURE;
    }

    // seek to end of file to determine filesize
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size == -1) {
        perror("Error determining file size");
        close(fd);
        return EXIT_FAILURE;
    }

    // seek to the beginning of the file
    if (lseek(fd, 0, SEEK_SET) == -1) {
        perror("Error resetting file position");
        close(fd);
        return EXIT_FAILURE;
    }

    // map the image file's metadata into our virtual memory
    void *metadata_map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (metadata_map == MAP_FAILED) {
        perror("Error mapping file for metadata");
        close(fd);
        return EXIT_FAILURE;
    }

    // extract number of memory regions from image file's metadata
    Header *header = (Header *)metadata_map;
    unsigned long num_entries = header->numEntries;
    printf("Image contains %lu memory regions\n", num_entries);

    // map each memory region into our virtual memory
    for (unsigned long i = 0; i < num_entries; i++) {
        Entry *entry = &header->entries[i];
        if (check_for_overlap(entry->start, entry->end)) {
            fprintf(stderr,
                    "Fatal error: Region %lu (%016lx-%016lx) overlaps with existing process memory.\n",
                    i, entry->start, entry->end);
            munmap(metadata_map, file_size);
            close(fd);
            return EXIT_FAILURE;
        }
    }

    // store information about the subcontext into global data structure
    MappedSubcontext *subctx = &mapped_subcontexts[num_mapped_subcontexts];
    strncpy(subctx->img_file, img_file, sizeof(subctx->img_file) - 1);
    subctx->img_file[sizeof(subctx->img_file) - 1] = '\0';
    subctx->fd = fd;
    subctx->num_entries = num_entries;
    subctx->is_active = 0;

    subctx->entries = malloc(num_entries * sizeof(Entry));
    // unmap the metadata
    if (!subctx->entries) {
        perror("Error allocating memory for entries");
        munmap(metadata_map, file_size);
        close(fd);
        return EXIT_FAILURE;
    }
    // copy over the entries pointer to the global data structure
    memcpy(subctx->entries, header->entries, num_entries * sizeof(Entry));

    // allocate memory for the header. copy pointer from previous header
    subctx->header = malloc(sizeof(Header));
    if (!subctx->header) {
        perror("Error allocating memory for header");
        free(subctx->entries);
        munmap(metadata_map, file_size);
        close(fd);
        return EXIT_FAILURE;
    }
    memcpy(subctx->header, header, sizeof(Header));

    for (unsigned long i = 0; i < num_entries; i++) {
        Entry *entry = &subctx->entries[i];
        size_t region_size = entry->end - entry->start;
        off_t  file_offset = entry->offsetIntoFile;

        printf("Mapping region %lu: %016lx-%016lx; Size: %zu bytes; Offset: %lu (NO PERMISSIONS)\n",
               i, entry->start, entry->end, region_size, file_offset);

        // map the previously recorded memory regions
        void *region_map = mmap((void *)entry->start, region_size,
                               PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_SHARED | MAP_FIXED, fd, file_offset);
        mprotect((void *)entry->start, region_size, PROT_READ | PROT_WRITE | PROT_EXEC);

        if (region_map == MAP_FAILED) {
            perror("Error mapping memory region");
            fprintf(stderr, "Failed to map region %lu at address %016lx\n", i, entry->start);
            for (unsigned long j = 0; j < i; j++) {
                Entry *prev = &subctx->entries[j];
                munmap((void *)prev->start, prev->end - prev->start);
            }
            free(subctx->entries);
            free(subctx->header);
            munmap(metadata_map, file_size);
            close(fd);
            return EXIT_FAILURE;
        }
        if (region_map != (void *)entry->start) {
            fprintf(stderr,
                    "Warning: Region %lu mapped at %p instead of requested %016lx\n",
                    i, region_map, entry->start);
        } else {
            printf("Successfully mapped region %lu at address %016lx (no permissions)\n",
                   i, entry->start);
        }
    }

    // record the base address and total size of the mapped memory regions in the data structure
    if (num_entries > 0) {
        subctx->base_addr = (void *)subctx->entries[0].start;
        subctx->total_size = subctx->entries[num_entries - 1].end - subctx->entries[0].start;
    }

    munmap(metadata_map, file_size);
    num_mapped_subcontexts++;
    printf("Successfully mapped subcontext from %s (index %zu)\n", img_file, num_mapped_subcontexts - 1);

    return fd;
}

/*
 * Basic helpers used by both the server and client libraries
 */
int check_for_overlap(unsigned long start, unsigned long end) {
    // TODO: cache this
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        perror("Error opening /proc/self/maps");
        return -1;
    }

    char line[256];
    int has_overlap = 0;
    while (fgets(line, sizeof(line), maps_file) != NULL) {
        unsigned long map_start, map_end;
        if (sscanf(line, "%lx-%lx", &map_start, &map_end) == 2) {
            if ((start <= map_end) && (end >= map_start)) {
                has_overlap = 1;
                printf("Overlap detected: %016lx-%016lx overlaps with %016lx-%016lx\n",
                       start, end, map_start, map_end);
                break;
            }
        }
    }
    fclose(maps_file);
    return has_overlap;
}

int perms_to_prot(const char *perm) {
    int prot = 0;
    // TODO: BUG: what if we have some but not all of the permissions?  Indices are incorrect.
    if (perm[0] == 'r') prot |= PROT_READ;
    if (perm[1] == 'w') prot |= PROT_WRITE;
    if (perm[2] == 'x') prot |= PROT_EXEC;
    return prot;
}

/*
 * Call a function from the mapped subcontext given a file descriptor to
 * the image file and the index of the function pointer stored in the
 * header.
 */
int call_subcontext_function(int func_idx, int fd) {
    Header *header;
    void *header_map = mmap(NULL, sizeof(Header), PROT_READ, MAP_PRIVATE, fd, 0);
    if (header_map == MAP_FAILED) {
        perror("Error mapping header for function call");
        return EXIT_FAILURE;
    }

    header = (Header *)header_map;

    if (func_idx < 0 || func_idx >= MAX_FUNC_PTRS || header->func_ptr[func_idx] == NULL) {
        fprintf(stderr, "Invalid function index or NULL function pointer\n");
        munmap(header_map, sizeof(Header));
        return EXIT_FAILURE;
    }

    void (*func)(int) = header->func_ptr[func_idx];
    printf("Calling function at address: %p\n", func);
    func(0);

    munmap(header_map, sizeof(Header));
    return EXIT_SUCCESS;
}

/*
 * Unmap a previously mapped subcontext given the file descriptor returned
 * by map_subcontext -- currently not tested.
 */
int unmap_subcontext(int fd) {
    for (size_t i = 0; i < num_mapped_subcontexts; i++) {
        MappedSubcontext *subctx = &mapped_subcontexts[i];
        if (subctx->fd == fd) {
            for (size_t j = 0; j < subctx->num_entries; j++) {
                Entry *entry = &subctx->entries[j];
                munmap((void *)entry->start, entry->end - entry->start);
            }
            free(subctx->entries);
            free(subctx->header);
            close(subctx->fd);
            for (size_t k = i; k + 1 < num_mapped_subcontexts; k++) {
                mapped_subcontexts[k] = mapped_subcontexts[k + 1];
            }
            num_mapped_subcontexts--;
            return 0;
        }
    }
    return -1;
}
