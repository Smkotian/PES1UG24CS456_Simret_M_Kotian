#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pes.h"
#include "index.h"

// forward declaration
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out);

// ==========================
// Helper for sorting
// ==========================
static int cmp_entries(const void *a, const void *b) {
    return strcmp(((const IndexEntry *)a)->path,
                  ((const IndexEntry *)b)->path);
}

// ==========================
// Find entry
// ==========================
IndexEntry *index_find(Index *index, const char *path) {
    for (int i = 0; i < index->count; i++) {
        if (strcmp(index->entries[i].path, path) == 0)
            return &index->entries[i];
    }
    return NULL;
}

// ==========================
// Load index
// ==========================
int index_load(Index *index) {
    index->count = 0;

    FILE *f = fopen(INDEX_FILE, "r");
    if (!f) return 0;

    char hex[HASH_HEX_SIZE + 1];

    while (index->count < MAX_INDEX_ENTRIES) {
        IndexEntry *e = &index->entries[index->count];

        int ret = fscanf(f, "%o %64s %lu %u %255s\n",
                         &e->mode,
                         hex,
                         &e->mtime_sec,
                         &e->size,
                         e->path);

        if (ret == EOF || ret < 5)
            break;

        if (hex_to_hash(hex, &e->hash) != 0) {
            fclose(f);
            return -1;
        }

        index->count++;
    }

    fclose(f);
    return 0;
}

// ==========================
// Save index
// ==========================
int index_save(const Index *index) {
    Index sorted = *index;

    qsort(sorted.entries, sorted.count,
          sizeof(IndexEntry), cmp_entries);

    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", INDEX_FILE);

    FILE *f = fopen(tmp_path, "w");
    if (!f) return -1;

    char hex[HASH_HEX_SIZE + 1];

    for (int i = 0; i < sorted.count; i++) {
        IndexEntry *e = &sorted.entries[i];

        hash_to_hex(&e->hash, hex);

        fprintf(f, "%o %s %lu %u %s\n",
                e->mode,
                hex,
                e->mtime_sec,
                e->size,
                e->path);
    }

    fflush(f);
    fsync(fileno(f));
    fclose(f);

    return rename(tmp_path, INDEX_FILE);
}

// ==========================
// Add file (FIXED SEGFAULT)
// ==========================
int index_add(Index *index, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", path);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);

    if (size < 0) {
        fclose(f);
        return -1;
    }

    fseek(f, 0, SEEK_SET);

    void *buf = malloc(size ? size : 1);
    if (!buf) {
        fclose(f);
        return -1;
    }

    if (size > 0 && fread(buf, 1, size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return -1;
    }

    fclose(f);

    ObjectID hash;
    if (object_write(OBJ_BLOB, buf, size, &hash) != 0) {
        free(buf);
        return -1;
    }

    free(buf);

    struct stat st;
    if (stat(path, &st) != 0)
        return -1;

    IndexEntry *entry = index_find(index, path);

    if (!entry) {
        if (index->count >= MAX_INDEX_ENTRIES)
            return -1;
        entry = &index->entries[index->count++];
    }

    strncpy(entry->path, path, sizeof(entry->path) - 1);
    entry->path[sizeof(entry->path) - 1] = '\0';

    entry->hash      = hash;
    entry->mode      = (st.st_mode & S_IXUSR) ? 0100755 : 0100644;
    entry->mtime_sec = st.st_mtime;
    entry->size      = st.st_size;

    return index_save(index);
}

// ==========================
// Status (needed by pes)
// ==========================
int index_status(const Index *index) {
    printf("Staged files:\n");
    for (int i = 0; i < index->count; i++) {
        printf("  %s\n", index->entries[i].path);
    }
    return 0;
}

