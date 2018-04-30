//encryption format from the openssl wiki
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

/* 32 byte key (256 bit key) */
#define AES_256_KEY_SIZE 32
/* 16 byte block size (128 bits) */
#define AES_BLOCK_SIZE 16
#define BUFSIZE 100

void insertNum(int num, char* str, int strlen){
    int digit = 0;
    for(int i = strlen-1; i >=0; i--){
        if(num == 0){
            *(str+i) = '0';
        }
        else{
            digit = num % 10;
            num = num /10;
            
            *(str+i) = digit + '0';
        }
    }
}


void file_encrypt_decrypt(cipher_params_t *params, FILE *ifp, FILE *ofp){
    /* Allow enough space in output buffer for additional block */
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];
    
    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;
    
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        //cleanup(params, ifp, ofp, ERR_EVP_CTX_NEW);
    }
    
    /* Don't set key or IV right away; we want to check lengths */
    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        //cleanup(params, ifp, ofp, ERR_EVP_CIPHER_INIT);
    }
    
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);
    
    /* Now we can set key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        //cleanup(params, ifp, ofp, ERR_EVP_CIPHER_INIT);
    }
    
    do {
        // Read in data in blocks until EOF. Update the ciphering with each read.
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
        //read error
        if (ferror(ifp)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            //cleanup(params, ifp, ofp, errno);
        }
        //update error
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            //cleanup(params, ifp, ofp, ERR_EVP_CIPHER_UPDATE);
        }
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        //write error
        if (ferror(ofp)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            //cleanup(params, ifp, ofp, errno);
        }
    
    } while (num_bytes_read >= BUFSIZE);
    
    /* Now cipher the final block and write it out to file */
    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        //bad decrypt - throws an error if the decrypt func finds something undexpected -> made our heapsort on the decrpyt results almost useless
        EVP_CIPHER_CTX_cleanup(ctx);
        //cleanup(params, ifp, ofp, ERR_EVP_CIPHER_FINAL);
    }
    else{
        //this is where we write to the buffer we want to tokenize
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    }
    
    if (ferror(ofp)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        //cleanup(params, ifp, ofp, errno);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}


int main(int argc, char *argv[]) {
    FILE *f_input, *f_enc, *f_dec;
    
    /* Make sure user provides the input file */
    if (argc != 2) {
        printf("Usage: %s /path/to/file\n", argv[0]);
        return -1;
    }
    
    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    if (!params) {
        /* Unable to allocate memory on heap*/
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return errno;
    }
    
    /* Key to use for encrpytion and decryption */
    unsigned char key[AES_256_KEY_SIZE];
    
    /* Initialization Vector */
    unsigned char iv[AES_BLOCK_SIZE];
    
    /* Generate cryptographically strong pseudo-random bytes for key and IV*/
    if (!RAND_bytes(key, sizeof(key)) || !RAND_bytes(iv, sizeof(iv))) {
        // OpenSSL reports a failure, act accordingly
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
    }

    /* our code for making a key that we can control*/
    char* foo;
    foo = (char*)malloc(sizeof(char)*AES_256_KEY_SIZE);
    insertNum(1, foo, AES_256_KEY_SIZE); // the int is the number in the key that will be prepended with 0's
    memcpy(key, foo, AES_256_KEY_SIZE);
    free(foo);
    
    params->key = key;
    params->iv = iv;
    
    /* Indicate that we want to encrypt */
    params->encrypt = 1;
    
    /* Set the cipher type you want for encryption-decryption */
    params->cipher_type = EVP_aes_256_cbc();
    
    /* Open the input file for reading in binary ("rb" mode) */
    f_input = fopen(argv[1], "rb");
    if (!f_input) {
        /* Unable to open file for reading */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    
    /* Open and truncate file to zero length or create ciphertext file for writing */
    f_enc = fopen("encrypted_file", "wb");
    if (!f_enc) {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    
    /* Encrypt the given file */
    file_encrypt_decrypt(params, f_input, f_enc);
    
    /* Encryption done, close the file descriptors */
    fclose(f_input);
    fclose(f_enc);
    
    /* Decrypt the file */
    /* Indicate that we want to decrypt */
    params->encrypt = 0;
    
    
    //here is where we insert our loop for key iteration
    for(int i = 0; i < 10; i++) {
    
        //make a guessed key based on the iteration index of the loop
        unsigned char* guessedKey[AES_256_KEY_SIZE];
        char* temp;
        temp = (char*)malloc(sizeof(char)*AES_256_KEY_SIZE);
        insertNum(i, temp, AES_256_KEY_SIZE); // the int is the number in the key that will be prepended with 0's
        memcpy(key, temp, AES_256_KEY_SIZE);
        free(temp);
        
        //alter params with the guessed key
        params->key = key;
        //keep the iv the same bc Kerckhoffs's principle say the attacker can know all except the key
    
        /* Open the encrypted file for reading in binary ("rb" mode) */
        f_input = fopen("encrypted_file", "rb");
        if (!f_input) {
            /* Unable to open file for reading */
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
            return errno;
        }
    
        /* Open and truncate file to zero length or create decrypted file for writing */
        f_dec = fopen("decrypted_file", "wb");
        if (!f_dec) {
            /* Unable to open file for writing */
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
            return errno;
        }
    
        /* Decrypt the given file */
        file_encrypt_decrypt(params, f_input, stdout); //f_dec instead of stdout
    }
    
    /* Close the open file descriptors */
    fclose(f_input);
    fclose(f_dec);
    
    /* Free the memory allocated to our structure */
    free(params);
    
    return 0;
}

/*
 To Read from decrypted file.
 Run into some weirdness with certain chracters/ lengths of text specifically on the third line of text.
 */
char *readMessageFromFile(FILE *out) {
    char *message;
    
    fseek(out, 0L, SEEK_END);
    long s = ftell(out);
    rewind(out);
    message = malloc(s);
    if ( message != NULL )
    {
        fread(message, s, 1, out);
        // we can now close the file
        fclose(out);
        out = NULL;
        
        return message;
    }
    return NULL;
}
