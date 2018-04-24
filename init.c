//encryption format from the openssl wiki
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>


int encrypt(unsigned char* plaintext, int plaintextLength, unsigned char* key, unsigned char* initvector, unsigned char* ciphertext){
    EVP_CIPHER_CTX* ctx; //context for the encryption
    int length;
    int ciphertextLength;
    
    //create and init the context
    if(!(ctx = EVP_CIPHER_CTX_new())){
        printf("failed to initialize the encryption context\n");
        return -1;
    }
    
    // here we choose which enryption scheme to use (but we have to make sure the key and initVector match the scheme's expected keysize and IV size)
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, initvector)){
        printf("encryption scheme initialization has failed\n");
        return -1;
    }
    
    //do the actual encryption of the plaintext
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintextLength)){
        printf("encryption of the message has failed\n");
        return -1;
    }
    ciphertextLength = length;
    
    //finalize encryption - may add more bytes to ciphertext
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + length, &length)){
        printf("encryption finalization failed");
        return -1;
    }
    ciphertextLength += length;
    
    // clean up the encryption context
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertextLength;
    
}


int main (int argc, char** argv){
    if (argc != 2){
        printf("Please include only a message as a command line argument\n");
        return 0;
    }
    
    int CIPHERTEXT_SIZE = 128;
    
    unsigned char* key = (unsigned char*) "00000000000000000000000000000001"; //256 bit string
    unsigned char* initializationVector = (unsigned char*) "0000000000000001";//128 bit string
    unsigned char* plaintext = (unsigned char*) argv[1];
    unsigned char encryptedText[CIPHERTEXT_SIZE];
    
    FILE* output = fopen("cipher.txt", "wb");
    
    int encryptedTextLength = encrypt(plaintext, strlen((char *) plaintext), key, initializationVector, encryptedText);
    
    BIO_dump_fp (output, (const char *)encryptedText, encryptedTextLength);
    BIO_dump_fp (stdout, (const char *)encryptedText, encryptedTextLength);
    
    return 0;
}




