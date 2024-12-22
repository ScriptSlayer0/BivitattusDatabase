#ifndef BDB_OQS_H
#define BDB_OQS_H
#include "types.h"

PATH catpath(PATH path1, PATH path2) {
    PATH full_path = (PATH)malloc(PATH_MAX);
    if (!full_path) return NULL;
    if (path1[OPENSSL_strnlen(path1, PATH_MAX) - 1] == '/') {
        snprintf(full_path, PATH_MAX, "%s%s", path1, path2);
    } else {
        snprintf(full_path, PATH_MAX, "%s/%s", path1, path2);
    }
    return full_path;
}

#ifdef __need_fsize
size_t fsize(FILE *file) {
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
    return size;
}
#undef __need_fsize
#endif

void free_key(KEY key) {
    if (key) {
        if (key->ctx) OQS_KEM_free(key->ctx);
        if (key->pub_key) free(key->pub_key);
        if (key->priv_key) free(key->priv_key);
        free(key);
    }
}

KEY gen_key() {
    KEY key = NULL;
    KEY_CTX kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;

    kem = OQS_KEM_new(KEYSIZE);
    if (!kem) return NULL;

    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    if (!public_key || !secret_key) {
        OQS_KEM_free(kem);
        free(public_key);
        free(secret_key);
        return NULL;
    }

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        free(public_key);
        free(secret_key);
        return NULL;
    }

    key = (KEY)malloc(sizeof(struct KEY));
    if (!key) {
        OQS_KEM_free(kem);
        free(public_key);
        free(secret_key);
        return NULL;
    }

    key->ctx = kem;
    key->pub_key = public_key;
    key->priv_key = secret_key;
    return key;
}

int save_pubkey(KEY pubkey, PATH dir) {
    int result = 1;
    FILE *file = NULL;
    char *encoded = NULL;
    PATH full_path = NULL;

    if (!pubkey || !dir) return 1;

    full_path = catpath(dir, PUB_KEYFILE);
    if (!full_path) return 1;

    file = fopen(full_path, "wb");
    if (!file) {
        free(full_path);
        return 1;
    }

    size_t key_size = pubkey->ctx->length_public_key;
    size_t enc_size = 4*((key_size+2)/3);
    encoded = (char *)malloc(enc_size + 1);  // +1 for null terminator
    if (!encoded) {
        fclose(file);
        free(full_path);
        return 1;
    }

    if (fwrite(PEM_HEADER_PUB, 1, PEM_HF_SIZE, file) != PEM_HF_SIZE ||
        b64encode((unsigned char *)encoded, pubkey->pub_key, (int)key_size) != 0 ||
        fwrite(encoded, 1, enc_size, file) != enc_size ||
        fwrite(PEM_FOOTER_PUB, 1, PEM_HF_SIZE, file) != PEM_HF_SIZE) {
        result = 1;
    } else {
        result = 0;
    }

    fclose(file);
    free(encoded);
    free(full_path);
    return result;
}

unsigned char *oqs_encrypt(KEY pub_key, size_t *encrypted_len, KEY_t *shared) {
    if (!pub_key || !encrypted_len) return NULL;

    KEY_CTX kem = pub_key->ctx;
    KEY_t shared_secret = malloc(kem->length_shared_secret);
    KEY_t ciphertext = malloc(kem->length_ciphertext);
    
    if (!shared_secret || !ciphertext) {
        free(shared_secret);
        free(ciphertext);
        *encrypted_len = 0;
        return NULL;
    }

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, pub_key->pub_key) != 0) {
        free(shared_secret);
        free(ciphertext);
        *encrypted_len = 0;
        return NULL;
    }

    *encrypted_len = kem->length_ciphertext;
    if (shared) {
        *shared = shared_secret;
    } else {
        free(shared_secret);
    }
    return ciphertext;
}

unsigned char *oqs_decrypt(KEY priv_key, unsigned char *ciphertext, size_t *decrypted_len) {
    if (!priv_key || !ciphertext || !decrypted_len) return NULL;

    KEY_CTX kem = priv_key->ctx;
    KEY_t shared_secret = malloc(kem->length_shared_secret);
    if (!shared_secret) {
        *decrypted_len = 0;
        return NULL;
    }

    *decrypted_len = kem->length_shared_secret;
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, priv_key->priv_key) != 0) {
        free(shared_secret);
        *decrypted_len = 0;
        return NULL;
    }

    return shared_secret;
}

#endif //BDB_OQS_H