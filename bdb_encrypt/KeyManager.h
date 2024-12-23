#include <stdbool.h>

#ifndef KEYMANAGER_H
#define KEYMANAGER_H

#define __need_fsize

#ifdef _WIN32
    #include <direct.h> // for mkdir on Windows
    #include <windows.h> // for checking db on Windows
#else
    #include <sys/types.h> // for mkdir on Unix-like systems
    #include <sys/stat.h> // for checking db on Unix
#endif

//#define BDB_USE_EXPERIMENTAL //uncomment to test under KEM instead of RSA
#ifdef BDB_USE_EXPERIMENTAL
    #include "liboqs/liboqs.h"
    #define bdb_encrypt oqs_fencrypt
    #define bdb_decrypt oqs_fdecrypt
#else 
    #include "rsa/rsa.h"
    #define bdb_encrypt RSA_fencrypt
    #define bdb_decrypt RSA_fdecrypt
#endif

#include "aes/aes.h"
#include "types.h"

typedef unsigned char key;

bool makedir(const PATH dir_name) {
    #ifdef _WIN32
        if (_mkdir(dir_name) != 0) return false;
    #else
        if (mkdir(dir_name, 0750) != 0) return false;
    #endif
    return true;
}

bool db_exists(const PATH db_name){
    #ifdef _WIN32
        DWORD attributes = GetFileAttributes(db_name);

        if (attributes == INVALID_FILE_ATTRIBUTES) {
            return makedir(db_name);
        }
        if (!(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
            return false;
        }   
    #else
        struct stat st;
        if (stat(db_name, &st)!=0) {
            return makedir(db_name);
        }
        if (!S_ISDIR(st.st_mode)) {
            return false;
        }
    #endif
    return true;
}

bool sym_key_exists(const PATH dir){
    PATH filepath = catpath(dir, SYMKEY_FILE);
    FILE *file = fopen(filepath, "r");
    if (!file) {
        return false;
    }
    fclose(file);
    return true;
}

int gen_keys(const PATH dir){
    if (sym_key_exists(dir)!=false){
        remove(catpath(dir, SYMKEY_FILE));
    }
    KEY keys = gen_key();
    save_pubkey(keys, dir);
    save_privkey(keys, dir);
    return 0;
}

int key_check(const PATH dir){
    FILE *privkeyfile = fopen(catpath(dir, PRIV_KEYFILE), "r");
    FILE *pubkeyfile = fopen(catpath(dir, PUB_KEYFILE), "r");
    if ((privkeyfile==NULL) && (pubkeyfile==NULL)){
        gen_keys(dir);
        key_check(dir);
    }
    return 0;
}

#endif // KEYMANAGER_H