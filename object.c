// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Determine the string representation of the object type
    const char *type_str = "";
    switch (type) {
        case OBJ_BLOB:   type_str = "blob"; break;
        case OBJ_TREE:   type_str = "tree"; break;
        case OBJ_COMMIT: type_str = "commit"; break;
        default: return -1;
    }

    // 2. Build the header: "<type> <size>\0"
    char header[128];
    int header_len = snprintf(header, sizeof(header), "%s %zu", type_str, len);
    header_len++; // Include the null terminator

    // 3. Allocate memory and combine header + data for hashing
    size_t full_len = header_len + len;
    uint8_t *full_buf = malloc(full_len);
    if (!full_buf) return -1;
   
    memcpy(full_buf, header, header_len);
    if (len > 0) {
        memcpy(full_buf + header_len, data, len);
    }

    // 4. Compute hash using the provided helper
    compute_hash(full_buf, full_len, id_out);

    // 5. Deduplication check
    if (object_exists(id_out)) {
        free(full_buf);
        return 0; // Already exists, success
    }

    // 6. Create shard directory if it doesn't exist
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);
    char dir_path[256];
    snprintf(dir_path, sizeof(dir_path), "%s/%.2s", OBJECTS_DIR, hex);

    struct stat st = {0};
    if (stat(dir_path, &st) == -1) {
        mkdir(dir_path, 0755);
    }

    // 7. Atomic Write: Write to temp file, fsync, then rename
    char temp_path[512];
    snprintf(temp_path, sizeof(temp_path), "%s/tmp_obj_XXXXXX", dir_path);
   
    int fd = mkstemp(temp_path);
    if (fd < 0) {
        free(full_buf);
        return -1;
    }

    if (write(fd, full_buf, full_len) != (ssize_t)full_len) {
        close(fd);
        unlink(temp_path); // Cleanup on write failure
        free(full_buf);
        return -1;
    }

    fsync(fd); // Ensure it hits the disk
    close(fd);

    char final_path[512];
    object_path(id_out, final_path, sizeof(final_path));

    if (rename(temp_path, final_path) != 0) {
        unlink(temp_path);
        free(full_buf);
        return -1;
    }

    free(full_buf);
    return 0;
}

int object_read(const ObjectID *id, ObjectType *type_out, void **data_out, size_t *len_out) {
    // 1. Get the file path
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open and read the entire file into memory
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size < 0) {
        fclose(f);
        return -1;
    }

    uint8_t *read_buf = malloc(file_size);
    if (!read_buf) {
        fclose(f);
        return -1;
    }

    if (fread(read_buf, 1, file_size, f) != (size_t)file_size) {
        free(read_buf);
        fclose(f);
        return -1;
    }
    fclose(f);

    // 3. Verify integrity: recompute hash and compare
    ObjectID computed_id;
    compute_hash(read_buf, file_size, &computed_id);
    if (memcmp(computed_id.hash, id->hash, HASH_SIZE) != 0) {
        free(read_buf);
        return -1; // Corrupted file
    }

    // 4. Parse the header to extract type and size
    char *null_byte = memchr(read_buf, '\0', file_size);
    if (!null_byte) {
        free(read_buf);
        return -1; // Malformed header
    }

    // Determine type string
    if (strncmp((char*)read_buf, "blob ", 5) == 0) {
        *type_out = OBJ_BLOB;
    } else if (strncmp((char*)read_buf, "tree ", 5) == 0) {
        *type_out = OBJ_TREE;
    } else if (strncmp((char*)read_buf, "commit ", 7) == 0) {
        *type_out = OBJ_COMMIT;
    } else {
        free(read_buf);
        return -1; // Unknown object type
    }

    // Extract size
    char *space = memchr(read_buf, ' ', null_byte - (char*)read_buf);
    if (!space) {
        free(read_buf);
        return -1;
    }
    *len_out = strtoull(space + 1, NULL, 10);

    // 5. Allocate and copy the actual data payload
    if (*len_out > 0) {
        *data_out = malloc(*len_out);
        if (!*data_out) {
            free(read_buf);
            return -1;
        }
        size_t header_len = (null_byte - (char*)read_buf) + 1;
        memcpy(*data_out, read_buf + header_len, *len_out);
    } else {
        *data_out = NULL;
    }

    free(read_buf);
    return 0;
}

