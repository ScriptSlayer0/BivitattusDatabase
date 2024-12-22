#ifndef BDB_RSA_H
#define BDB_RSA_H

#include "types.h"

PATH catpath(PATH path1, PATH path2) {
    PATH full_path = (PATH)malloc(PATH_MAX);

    if (path1[OPENSSL_strnlen(path1, PATH_MAX) - 1] == '/') {
        snprintf(full_path, PATH_MAX, "%s%s", path1, path2);
    } else {
        snprintf(full_path, PATH_MAX, "%s/%s", path1, path2);
    }

    return full_path;
}

void handle_openssl_error() {
    ERR_print_errors_fp(stderr);
    abort();
}

KEY gen_key() {
    init_openssl();
    KEY pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) handle_openssl_error();
    if (EVP_PKEY_keygen_init(ctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEYSIZE) <= 0) handle_openssl_error();
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handle_openssl_error();

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

int save_pubkey(KEY key, PATH dir) {
    FILE *file = fopen(catpath(dir, PUB_KEYFILE), "wb");
    if (!file) {
        perror("Failed to open public key file");
        return 0;
    }
    if (!PEM_write_PUBKEY(file, key)) {
        fclose(file);
        handle_openssl_error();
    }
    fclose(file);
    return 1;
}

int save_privkey(KEY key, char *dir) {
    FILE *file = fopen(catpath(dir, PRIV_KEYFILE), "wb");
    if (!file) {
        perror("Failed to open private key file");
        return 0;
    }
    if (!PEM_write_PrivateKey(file, key, NULL, NULL, 0, NULL, NULL)) {
        fclose(file);
        handle_openssl_error();
    }
    fclose(file);
    return 1;
}

KEY load_pubkey(PATH dir) {
    init_openssl();
    FILE *file = fopen(catpath(dir, PUB_KEYFILE), "rb");
    if (!file) {
        perror("Failed to open public key file");
        return NULL;
    }
    KEY key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    fclose(file);
    if (!key) handle_openssl_error();
    return key;
}

KEY load_privkey(PATH dir) {
    init_openssl();
    FILE *file = fopen(catpath(dir, PRIV_KEYFILE), "rb");
    if (!file) {
        perror("Failed to open private key file");
        return NULL;
    }
    KEY key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    fclose(file);
    if (!key) handle_openssl_error();
    return key;
}

KEY_t gen_shared_key(){
    unsigned char *buffer = malloc(SHARED_KEYSIZE);
    if (!buffer) return NULL;
    if (RAND_bytes(buffer, SHARED_KEYSIZE) != 1) {
        free(buffer); // Freeing memory in case of error
        return NULL;
    }
    return buffer;
}

unsigned char *rsa_encrypt(KEY pub_key, size_t *encrypted_len, KEY_t *plain) {
    init_openssl();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pub_key, NULL);
    if (!ctx) handle_openssl_error();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handle_openssl_error();
    KEY_t plaintext = gen_shared_key();
    if (plain != NULL) {
        *plain = plaintext;
    }
    // Determine buffer size for encrypted data
    if (EVP_PKEY_encrypt(ctx, NULL, encrypted_len, plaintext, SHARED_KEYSIZE) <= 0) handle_openssl_error();

    unsigned char *encrypted = malloc(*encrypted_len);
    if (!encrypted) {
        perror("Failed to allocate memory for encryption");
        EVP_PKEY_CTX_free(ctx);
        free(plaintext); // Freeing memory in case of error
        return NULL;
    }

    // Perform encryption
    if (EVP_PKEY_encrypt(ctx, encrypted, encrypted_len, plaintext, SHARED_KEYSIZE) <= 0) {
        free(encrypted);
        EVP_PKEY_CTX_free(ctx);
        free(plaintext); // Freeing memory in case of error
        handle_openssl_error();
    }

    EVP_PKEY_CTX_free(ctx);
    free(plaintext); // Freeing memory after encryption
    return encrypted;
}

unsigned char *rsa_decrypt(KEY priv_key, unsigned char *ciphertext, size_t ciphertext_len) {
    init_openssl();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!ctx) handle_openssl_error();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handle_openssl_error();
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handle_openssl_error();

    size_t outlen;
    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, ciphertext, ciphertext_len) <= 0) {
        EVP_PKEY_CTX_free(ctx); // Freeing memory in case of error
        handle_openssl_error();
    }

    unsigned char *decrypted = malloc(outlen);
    if (!decrypted) {
        EVP_PKEY_CTX_free(ctx); // Freeing memory in case of error
        handle_openssl_error();
    }

    // Perform decryption
    if (EVP_PKEY_decrypt(ctx, decrypted, &outlen, ciphertext, ciphertext_len) <= 0) {
        free(decrypted);
        EVP_PKEY_CTX_free(ctx); // Freeing memory in case of error
        handle_openssl_error();
    }

    EVP_PKEY_CTX_free(ctx);
    return decrypted;
}

#ifdef __need_fsize
size_t fsize(FILE *file){
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
    return size;
}
#undef __need_fsize
#endif

int RSA_fencrypt(KEY pub_key, PATH filepath, KEY_t *shared){
    size_t enc_len;
    unsigned char *encrypted = rsa_encrypt(pub_key, &enc_len, shared);
    if (!encrypted) return 1; // Check if encryption failed
    FILE *outfile = fopen(filepath, "wb");
    if (!outfile) {
        free(encrypted); // Release memory in case of error
        return 1;
    }
    fwrite(encrypted, 1, enc_len, outfile);
    fclose(outfile);
    free(encrypted); // Freeing memory after writing to the file
    return 0;
}

KEY_t RSA_fdecrypt(KEY priv_key, PATH filepath){
    FILE *infile = fopen(filepath, "rb");
    if (!infile) return NULL;
    size_t size = fsize(infile);
    unsigned char *ciphertext = (unsigned char *)malloc(size);
    if (!ciphertext) {
        fclose(infile); Release memory in case of error
        return NULL;
    }
    fread(ciphertext, 1, size, infile);
    fclose(infile);
    KEY_t decrypted = rsa_decrypt(priv_key, ciphertext, size);
    free(ciphertext); // Freeing memory after decryption
    return decrypted;
}

#endif //BDB_RSA_H
