#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include "bdb_encrypt/FileEncrypter.h"

#define MAXFILENAME 256 // should be about 256 for most systems
#define TESTNAME "test.db" // use for testing this code
#define PATHSIZE ((MAXFILENAME*2)+1)

// Database Struct
typedef struct {
    char tablename[MAXFILENAME];
    long datasize;
} SetHeader;

#define HEADERSIZE sizeof(SetHeader)

// Other useful functions
FILE* open_file(const PATH dir, const PATH filename, const char* mode) {
    // Validate mode string before comparison
    if (str_len(mode) != 1 && str_len(mode) != 2) {
        fprintf(stderr, "Invalid mode string\n");
        exit(EXIT_FAILURE);
    }

    // Compare characters directly instead of string pointers
    if (mode[0] != 'w') {
        KEY privkey = load_privkey(dir);
        if (decrypt_file(dir, filename, privkey) != 0) {
            fprintf(stderr, "Error decrypting the file: %s\n", filename);
            exit(EXIT_FAILURE);
        }
    }

    // Create temporary mutable copies for path construction
    PATH temp_dir = strdup(dir);
    if (!temp_dir) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    PATH temp_filename = strdup(filename);
    if (!temp_filename) {
        free(temp_dir);
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    // Create the full path
    PATH temp_slash = strdup("/");
    if (!temp_slash) {
        free(temp_dir);
        free(temp_filename);
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    PATH intermediate = catpath(temp_dir, temp_slash);
    if (!intermediate) {
        free(temp_dir);
        free(temp_filename);
        free(temp_slash);
        fprintf(stderr, "Path construction failed\n");
        exit(EXIT_FAILURE);
    }

    PATH filepath = catpath(intermediate, temp_filename);
    if (!filepath) {
        free(temp_dir);
        free(temp_filename);
        free(temp_slash);
        free(intermediate);
        fprintf(stderr, "Path construction failed\n");
        exit(EXIT_FAILURE);
    }

    FILE* file = fopen(filepath, mode);
    if (!file) {
        fprintf(stderr, "Error opening the file: %s\n", filename);
    }

    // Cleanup
    free(temp_dir);
    free(temp_filename);
    free(temp_slash);
    free(intermediate);
    free(filepath);

    if (!file) {
        exit(EXIT_FAILURE);
    }

    return file;
}

int close_file(const PATH dir, const PATH filename, FILE *file) {
    fclose(file);
    
    PATH temp_dir = strdup(dir);
    if (!temp_dir) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    PATH temp_slash = strdup("/");
    if (!temp_slash) {
        free(temp_dir);
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    PATH path = catpath(temp_dir, temp_slash);
    if (!path) {
        free(temp_dir);
        free(temp_slash);
        fprintf(stderr, "Path construction failed\n");
        exit(EXIT_FAILURE);
    }

    KEY privkey = load_privkey(dir);
    if (encrypt_file(path, filename, privkey)) {
        free(temp_dir);
        free(temp_slash);
        free(path);
        fprintf(stderr, "Error encrypting the file: %s\n", filename);
        exit(EXIT_FAILURE);
    }

    free(temp_dir);
    free(temp_slash);
    free(path);
    return 0;
}

bool CheckDataSet(const char* tablename) {
    FILE* file = fopen(tablename, "r");
    if (file) {
        fclose(file);
        return true; // Success
    } else {
        return false;
    }
}

size_t str_len(const char *str) {
    const char *start = str;           // Save start address
    while (*str != '\0') {
        str++;                         // loop through characters until terminator is found
    }
    return str - start;                // return the difference in memory address for length
}
