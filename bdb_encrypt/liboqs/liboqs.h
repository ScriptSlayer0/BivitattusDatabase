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
size_t fsize(FILE *file){
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);
    return size;
}
#undef __need_fsize
#endif

KEY gen_key(){
    KEY key = NULL;
    KEY_CTX kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_enc = NULL;
    uint8_t *shared_secret_dec = NULL;

    kem = OQS_KEM_new(KEYSIZE);
    if (!kem) goto cleanup;

    public_key = malloc(kem->length_public_key);
    secret_key = malloc(kem->length_secret_key);
    ciphertext = malloc(kem->length_ciphertext);
    shared_secret_enc = malloc(kem->length_shared_secret);
    shared_secret_dec = malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext || !shared_secret_enc || !shared_secret_dec) 
        goto cleanup;

    if (OQS_KEM_keypair(kem, public_key, secret_key) != OQS_SUCCESS) 
        goto cleanup;

    key = (KEY)malloc(sizeof(struct KEY));
    if (!key) goto cleanup;

    key->ctx = kem;
    key->pub_key = public_key;
    key->priv_key = secret_key;

    // Success, prevent cleanup of these items
    kem = NULL;
    public_key = NULL;
    secret_key = NULL;

cleanup:
    if (kem) OQS_KEM_free(kem);
    free(public_key);
    free(secret_key);
    free(ciphertext);
    free(shared_secret_enc);
    free(shared_secret_dec);

    return key;
}

int save_pubkey(KEY pubkey, PATH dir){
    int result = 1;
    FILE *file = NULL;
    char *encoded = NULL;
    PATH full_path = NULL;

    full_path = catpath(dir, PUB_KEYFILE);
    if (!full_path) goto cleanup;

    file = fopen(full_path, "wb");
    if (!file) goto cleanup;

    if (fwrite(PEM_HEADER_PUB, 1, PEM_HF_SIZE, file) != PEM_HF_SIZE) goto cleanup;

    size_t key_size = pubkey->ctx->length_public_key;
    KEY_t key = pubkey->pub_key;
    size_t enc_size = 4*((key_size+2)/3);
    encoded = (char *)malloc(enc_size);
    if (!encoded) goto cleanup;

    b64encode((unsigned char *)encoded, key, (int)key_size);
    if (fwrite(encoded, 1, enc_size, file) != enc_size) goto cleanup;

    if (fwrite(PEM_FOOTER_PUB, 1, PEM_HF_SIZE, file) != PEM_HF_SIZE) goto cleanup;

    result = 0;  // Success

cleanup:
    if (file) fclose(file);
    free(encoded);
    free(full_path);
    return result;
}

int save_privkey(KEY privkey, PATH dir){
    int result = 1;
    FILE *file = NULL;
    char *encoded = NULL;
    PATH full_path = NULL;

    full_path = catpath(dir, PRIV_KEYFILE);
    if (!full_path) goto cleanup;

    file = fopen(full_path, "wb");
    if (!file) goto cleanup;

    if (fwrite(PEM_HEADER_PRIV, 1, PEM_HF_SIZE, file) != PEM_HF_SIZE) goto cleanup;

    size_t key_size = privkey->ctx->length_secret_key;
    KEY_t key = privkey->priv_key;
    size_t enc_size = 4*((key_size+2)/3);
    encoded = (char *)malloc(enc_size);
    if (!encoded) goto cleanup;

    b64encode((unsigned char *)encoded, key, (int)key_size);
    if (fwrite(encoded, 1, enc_size, file) != enc_size) goto cleanup;

    if (fwrite(PEM_FOOTER_PRIV, 1, PEM_HF_SIZE, file) != PEM_HF_SIZE) goto cleanup;

    result = 0;  // Success

cleanup:
    if (file) fclose(file);
    free(encoded);
    free(full_path);
    return result;
}

int check_header(FILE *file, char *HEADER){
    char *header = malloc(PEM_HF_SIZE);
    if (!header) return -1;

    if (fread(header, 1, PEM_HF_SIZE, file) != PEM_HF_SIZE) {
        free(header);
        return -1;
    }

    int result = strcmp(header, HEADER);
    free(header);
    return result == 0 ? 0 : -1;
}

KEY load_pubkey(PATH dir){
    KEY key = NULL;
    FILE *file = NULL;
    char *encoded = NULL;
    unsigned char *decoded = NULL;
    PATH full_path = NULL;

    full_path = catpath(dir, PUB_KEYFILE);
    if (!full_path) goto cleanup;

    file = fopen(full_path, "rb");
    if (!file) goto cleanup;

    if (check_header(file, PEM_HEADER_PUB) < 0) goto cleanup;

    fseek(file, -PEM_HF_SIZE, SEEK_END);
    size_t key_size = ftell(file) - PEM_HF_SIZE;
    fseek(file, PEM_HF_SIZE, SEEK_SET);

    encoded = malloc(key_size);
    if (!encoded) goto cleanup;

    if (fread(encoded, 1, key_size, file) != key_size) goto cleanup;

    if (check_header(file, PEM_FOOTER_PUB) < 0) goto cleanup;

    size_t decoded_len = ((key_size * 3) / 4) - 1;
    decoded = malloc(decoded_len + 1);
    if (!decoded) goto cleanup;

    b64decode(decoded, (unsigned char *)encoded, key_size);

    KEY_CTX kem = OQS_KEM_new(KEYSIZE);
    if (!kem) goto cleanup;

    size_t keysize = kem->length_public_key;
    if (decoded_len != keysize) {
        OQS_KEM_free(kem);
        goto cleanup;
    }

    key = (KEY)malloc(sizeof(struct KEY));
    if (!key) {
        OQS_KEM_free(kem);
        goto cleanup;
    }

    key->ctx = kem;
    key->pub_key = decoded;
    decoded = NULL;  // Prevent cleanup

cleanup:
    if (file) fclose(file);
    free(encoded);
    free(decoded);
    free(full_path);
    return key;
}

KEY load_privkey(PATH dir){
    KEY key = NULL;
    FILE *file = NULL;
    char *encoded = NULL;
    unsigned char *decoded = NULL;
    PATH full_path = NULL;

    full_path = catpath(dir, PRIV_KEYFILE);
    if (!full_path) goto cleanup;

    file = fopen(full_path, "rb");
    if (!file) goto cleanup;

    if (check_header(file, PEM_HEADER_PRIV) < 0) goto cleanup;

    fseek(file, -PEM_HF_SIZE, SEEK_END);
    size_t key_size = ftell(file) - PEM_HF_SIZE;
    fseek(file, PEM_HF_SIZE, SEEK_SET);

    encoded = malloc(key_size);
    if (!encoded) goto cleanup;

    if (fread(encoded, 1, key_size, file) != key_size) goto cleanup;

    if (check_header(file, PEM_FOOTER_PRIV) < 0) goto cleanup;

    size_t decoded_len = ((key_size * 3) / 4);
    decoded = malloc(decoded_len + 1);
    if (!decoded) goto cleanup;

    b64decode(decoded, (unsigned char *)encoded, key_size);

    KEY_CTX kem = OQS_KEM_new(KEYSIZE);
    if (!kem) goto cleanup;

    size_t keysize = kem->length_secret_key;
    if (decoded_len != keysize) {
        OQS_KEM_free(kem);
        goto cleanup;
    }

    key = (KEY)malloc(sizeof(struct KEY));
    if (!key) {
        OQS_KEM_free(kem);
        goto cleanup;
    }

    key->ctx = kem;
    key->priv_key = decoded;
    decoded = NULL;  // Prevent cleanup

cleanup:
    if (file) fclose(file);
    free(encoded);
    free(decoded);
    free(full_path);
    return key;
}

unsigned char *oqs_encrypt(KEY pub_key, size_t *encrypted_len, KEY_t *shared){
    KEY_CTX kem = pub_key->ctx;
    KEY_t shared_secret = malloc(kem->length_shared_secret);
    KEY_t ciphertext = malloc(kem->length_ciphertext);
    
    if (!shared_secret || !ciphertext) {
        free(shared_secret);
        free(ciphertext);
        return NULL;
    }

    if (OQS_KEM_encaps(kem, ciphertext, shared_secret, pub_key->pub_key) != 0) {
        free(shared_secret);
        free(ciphertext);
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

unsigned char *oqs_decrypt(KEY priv_key, unsigned char *ciphertext, size_t *decrypted_len){
    KEY_CTX kem = priv_key->ctx;
    KEY_t shared_secret = malloc(kem->length_shared_secret);
    if (!shared_secret) return NULL;

    *decrypted_len = kem->length_shared_secret;
    if (OQS_KEM_decaps(kem, shared_secret, ciphertext, priv_key->priv_key) != 0) {
        free(shared_secret);
        return NULL;
    }

    return shared_secret;
}

int oqs_fencrypt(KEY pub_key, PATH filepath, KEY_t *shared){
    size_t enc_len;
    unsigned char *encrypted = oqs_encrypt(pub_key, &enc_len, shared);
    if (!encrypted) return 1;

    FILE *outfile = fopen(filepath, "wb");
    if (!outfile) {
        free(encrypted);
        return 1;
    }

    size_t written = fwrite(encrypted, 1, enc_len, outfile);
    fclose(outfile);
    free(encrypted);

    return (written == enc_len) ? 0 : 1;
}

unsigned char *oqs_fdecrypt(KEY priv_key, PATH filepath){
    FILE *infile = fopen(filepath, "rb");
    if (!infile) return NULL;

    size_t size = fsize(infile);
    unsigned char *ciphertext = (unsigned char *)malloc(size);
    if (!ciphertext) {
        fclose(infile);
        return NULL;
    }

    if (fread(ciphertext, 1, size, infile) != size) {
        fclose(infile);
        free(ciphertext);
        return NULL;
    }
    fclose(infile);

    size_t dec_len;
    unsigned char *decrypted = oqs_decrypt(priv_key, ciphertext, &dec_len);
    free(ciphertext);

    return decrypted;
}

#endif //BDB_OQS_H
