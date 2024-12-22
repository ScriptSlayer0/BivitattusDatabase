#ifndef BDB_OQS_H
#define BDB_OQS_H
#include "types.h"

PATH catpath(PATH path1, PATH path2) {
    if (!path1 || !path2) return NULL;
    
    size_t len1 = OPENSSL_strnlen(path1, PATH_MAX);
    size_t len2 = OPENSSL_strnlen(path2, PATH_MAX);
    
    // Validar todas las condiciones antes de asignar memoria
    if (len1 == 0 || len1 >= PATH_MAX || len2 >= PATH_MAX || (len1 + len2 + 2) > PATH_MAX) {
        return NULL;
    }
    
    PATH full_path = (PATH)malloc(PATH_MAX);
    if (!full_path) return NULL;
    
    if (path1[len1 - 1] == '/') {
        if (snprintf(full_path, PATH_MAX, "%s%s", path1, path2) >= PATH_MAX) {
            free(full_path);
            return NULL;
        }
    } else {
        if (snprintf(full_path, PATH_MAX, "%s/%s", path1, path2) >= PATH_MAX) {
            free(full_path);
            return NULL;
        }
    }
    return full_path;
}

#ifdef __need_fsize
size_t fsize(FILE *file) {
    if (!file) return 0;
    
    if (fseek(file, 0, SEEK_END) != 0) return 0;
    size_t size = ftell(file);
    if (fseek(file, 0, SEEK_SET) != 0) return 0;
    
    return size;
}
#undef __need_fsize
#endif

void cleanup_key(KEY *key) {
    if (key && *key) {
        if ((*key)->ctx) OQS_KEM_free((*key)->ctx);
        if ((*key)->pub_key) {
            OPENSSL_cleanse((*key)->pub_key, (*key)->ctx->length_public_key);
            free((*key)->pub_key);
        }
        if ((*key)->priv_key) {
            OPENSSL_cleanse((*key)->priv_key, (*key)->ctx->length_secret_key);
            free((*key)->priv_key);
        }
        OPENSSL_cleanse(*key, sizeof(struct KEY));
        free(*key);
        *key = NULL;
    }
}

KEY gen_key() {
    KEY key = NULL;
    KEY_CTX kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;

    do {
        kem = OQS_KEM_new(KEYSIZE);
        if (!kem) break;

        public_key = malloc(kem->length_public_key);
        secret_key = malloc(kem->length_secret_key);
        if (!public_key || !secret_key) break;

        if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) break;

        key = (KEY)malloc(sizeof(struct KEY));
        if (!key) break;

        key->ctx = kem;
        key->pub_key = public_key;
        key->priv_key = secret_key;
        return key;

    } while(0);

    // Cleanup on error
    if (kem) OQS_KEM_free(kem);
    if (public_key) {
        OPENSSL_cleanse(public_key, kem ? kem->length_public_key : 0);
        free(public_key);
    }
    if (secret_key) {
        OPENSSL_cleanse(secret_key, kem ? kem->length_secret_key : 0);
        free(secret_key);
    }
    return NULL;
}

int save_pubkey(KEY pubkey, PATH dir) {
    int result = 1;
    FILE *file = NULL;
    char *encoded = NULL;
    PATH full_path = NULL;

    if (!pubkey || !dir || !pubkey->ctx || !pubkey->pub_key) return 1;

    do {
        full_path = catpath(dir, PUB_KEYFILE);
        if (!full_path) break;

        file = fopen(full_path, "wb");
        if (!file) break;

        size_t key_size = pubkey->ctx->length_public_key;
        size_t enc_size = 4*((key_size+2)/3) + 1;  // +1 for null terminator
        encoded = (char *)malloc(enc_size);
        if (!encoded) break;

        if (fwrite(PEM_HEADER_PUB, 1, PEM_HF_SIZE, file) != PEM_HF_SIZE ||
            b64encode((unsigned char *)encoded, pubkey->pub_key, (int)key_size) != 0 ||
            fwrite(encoded, 1, enc_size-1, file) != enc_size-1 ||  // -1 to not write null terminator
            fwrite(PEM_FOOTER_PUB, 1, PEM_HF_SIZE, file) != PEM_HF_SIZE) {
            break;
        }

        result = 0;
    } while(0);

    if (file) fclose(file);
    if (encoded) {
        OPENSSL_cleanse(encoded, enc_size);
        free(encoded);
    }
    if (full_path) free(full_path);
    return result;
}

unsigned char *oqs_encrypt(KEY pub_key, size_t *encrypted_len, KEY_t *shared) {
    if (!pub_key || !encrypted_len || !pub_key->ctx || !pub_key->pub_key) {
        if (encrypted_len) *encrypted_len = 0;
        return NULL;
    }

    KEY_CTX kem = pub_key->ctx;
    KEY_t shared_secret = NULL;
    KEY_t ciphertext = NULL;
    
    do {
        shared_secret = malloc(kem->length_shared_secret);
        ciphertext = malloc(kem->length_ciphertext);
        if (!shared_secret || !ciphertext) break;

        if (OQS_KEM_encaps(kem, ciphertext, shared_secret, pub_key->pub_key) != OQS_SUCCESS) break;

        *encrypted_len = kem->length_ciphertext;
        if (shared) {
            *shared = shared_secret;
            shared_secret = NULL;  // Prevent cleanup
        }
        return ciphertext;

    } while(0);

    // Cleanup on error
    if (shared_secret) {
        OPENSSL_cleanse(shared_secret, kem->length_shared_secret);
        free(shared_secret);
    }
    if (ciphertext) {
        OPENSSL_cleanse(ciphertext, kem->length_ciphertext);
        free(ciphertext);
    }
    *encrypted_len = 0;
    return NULL;
}

unsigned char *oqs_decrypt(KEY priv_key, unsigned char *ciphertext, size_t *decrypted_len) {
    if (!priv_key || !ciphertext || !decrypted_len || !priv_key->ctx || !priv_key->priv_key) {
        if (decrypted_len) *decrypted_len = 0;
        return NULL;
    }

    KEY_CTX kem = priv_key->ctx;
    KEY_t shared_secret = NULL;

    do {
        shared_secret = malloc(kem->length_shared_secret);
        if (!shared_secret) break;

        if (OQS_KEM_decaps(kem, shared_secret, ciphertext, priv_key->priv_key) != OQS_SUCCESS) break;

        *decrypted_len = kem->length_shared_secret;
        return shared_secret;

    } while(0);

    // Cleanup on error
    if (shared_secret) {
        OPENSSL_cleanse(shared_secret, kem->length_shared_secret);
        free(shared_secret);
    }
    *decrypted_len = 0;
    return NULL;
}

#endif //BDB_OQS_H