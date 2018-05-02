//encryption format from the openssl wiki
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include <omp.h>

typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

struct probableMessage{
    double probability;
    char* message;
};

double countProbEnglWords(char str[]);
int search(char word[]);
void sorting(struct probableMessage* pm, int SIZE, FILE* out);
int comparator(const void* p, const void* q);
char *readMessageFromFile(FILE *out);
void plog(char *output);

struct probableMessage* results;

/* 32 byte key (256 bit key) */
#define AES_256_KEY_SIZE 32
/* 16 byte block size (128 bits) */
#define AES_BLOCK_SIZE 16
#define BUFSIZE 100
int const KEYSPACESIZE = 1000;

int logging = 1;

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
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size + 1];

    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;
    
    
    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        //cleanup(params, ifp, ofp, ERR_EVP_CTX_NEW);
    }
    plog("woop3\n");
    /* Don't set key or IV right away; we want to check lengths */
    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        //cleanup(params, ifp, ofp, ERR_EVP_CIPHER_INIT);
    }
    plog("woop4\n");
    OPENSSL_assert(((int)EVP_CIPHER_CTX_key_length(ctx)) == ((int)AES_256_KEY_SIZE));
    plog("innerwoop");
    OPENSSL_assert(((int)EVP_CIPHER_CTX_iv_length(ctx)) == ((int)AES_BLOCK_SIZE));
    plog("kokokokoko");
    
    /* Now we can set key and IV */
    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        plog("eeeeekekekekeke");
        EVP_CIPHER_CTX_cleanup(ctx);
        //cleanup(params, ifp, ofp, ERR_EVP_CIPHER_INIT);
    }
    
    
   plog("woop5\n");
    do {
        // Read in data in blocks until EOF. Update the ciphering with each read.
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
        //read error
        if (ferror(ifp)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            //cleanup(params, ifp, ofp, errno);
        }
       // printf("woop6\n");
        //update error
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            out_buf[0] = '\0';
            out_len = 1;
            //cleanup(params, ifp, ofp, ERR_EVP_CIPHER_UPDATE);
        }
      //  printf("woop7\n");
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        //write error
        if (ferror(ofp)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            //cleanup(params, ifp, ofp, errno);
        }
    
    } while (num_bytes_read >= BUFSIZE);
    plog("woop8\n");
    /* Now cipher the final block and write it out to file */
    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        //bad decrypt - throws an error if the decrypt func finds something undexpected -> made our heapsort on the decrpyt results almost useless
        out_buf[0] = '\0';
        out_len = 1;
        EVP_CIPHER_CTX_cleanup(ctx);
        //cleanup(params, ifp, ofp, ERR_EVP_CIPHER_FINAL);
    }
        //this is where we write to the file that is read into the buffer we want to tokenize
    plog("woop9\n");
    out_buf[out_len] = '\0';
    fwrite(out_buf, sizeof(unsigned char), (out_len + 1), ofp);
    
    if (ferror(ofp)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        //cleanup(params, ifp, ofp, errno);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}


int main(int argc, char *argv[]) {
    FILE*f_enc, *f_dec,*outfile;
  
    
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
    
    char* temp;
    temp = (char*)malloc(sizeof(char)*AES_BLOCK_SIZE);
    insertNum(3, temp, AES_BLOCK_SIZE);
    
    memcpy(iv, temp, AES_BLOCK_SIZE);
    free(temp);
    params->iv = iv;
    
    /* Decrypt the file */
    /* Indicate that we want to decrypt */
    /* Set the cipher type you want for encryption-decryption */
    params->cipher_type = EVP_aes_256_cbc();
    params->encrypt = 0;
    
    
    results = (struct probableMessage*)malloc(sizeof(struct probableMessage)*KEYSPACESIZE);
    
    fflush(stdout);
    
    
    //here is where we insert our loop for key iteration

#pragma omp parallel for
    for(int i = 0; i < KEYSPACESIZE; i++){
        
        /* Open the encrypted file for reading in binary ("rb" mode) */
        FILE* f_input2 = fopen("encrypted_file", "rb");
        if (!f_input2) {
            /* Unable to open file for reading */
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
            return errno;
        }
        
    
        //make a guessed key based on the iteration index of the loop
        unsigned char* guessedKey[AES_256_KEY_SIZE];
        char* temp;
        temp = (char*)malloc(sizeof(char)*AES_256_KEY_SIZE);
        insertNum(i, temp, AES_256_KEY_SIZE);
       
        memcpy(key, temp, AES_256_KEY_SIZE);
        free(temp);
        
        //alter params with the guessed key
        params->key = key;
        //keep the iv the same bc Kerckhoffs's principle say the attacker can know all except the key
    
        
        
        char* decrypted_phrase;
        char filename[36];
        sprintf(filename, "decry%d", i);
    
        plog("woop\n");
        
        outfile = fopen(filename, "wb");
        if (!outfile) {
            /* Unable to open file for writing */
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
            return errno;
        }
        
        
        /* Decrypt the given file */
        file_encrypt_decrypt(params, f_input2, outfile); //f_dec instead of decrypted_phrase to print to file
        plog("finished decrypt");
        fclose(outfile);
        plog("finished close");
        
        
        outfile = fopen(filename, "rb");
        if (!outfile) {
            /* Unable to open file for writing */
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
            return errno;
        }
        
        
        plog("fool1");
        
        decrypted_phrase = readMessageFromFile(outfile);
        char* decrypted_phrase_copy;
        decrypted_phrase_copy = (char *)malloc(sizeof(char) *strlen(decrypted_phrase) + 1);
        plog("fool1.5");
        
        strcpy(decrypted_phrase_copy, decrypted_phrase);
        plog("we playin now");
        fclose(outfile);
        plog("fool2");
        
        double percent = countProbEnglWords(decrypted_phrase);
        struct probableMessage currentMessage;
        currentMessage.message = decrypted_phrase_copy;
        currentMessage.probability = percent;
        plog("fool3");
        
        results[i] = currentMessage;
        fclose(f_input2);
    
        //free(decrypted_phrase);
    }
    
    /* Open and truncate file to zero length or create decrypted file for writing */
    f_dec = fopen("probable_decryptions", "wb");
    if (!f_dec) {
        /* Unable to open file for writing */
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }
    
    sorting(results, KEYSPACESIZE, f_dec);
    
    /* Close the open file descriptors */
    
    fclose(f_dec);
    
    /* Free the memory allocated to our structure */
    free(params);
    
    return 0;
}

double countProbEnglWords(char str[]) {
    const int MAX_WORDS = 50;
    const int MAX_CHARS = 100;
    char c[MAX_WORDS][MAX_CHARS];
    int possible_words = 0;
    double words = 0;
    const char delim[2] = " ";
    
    char *token;
    char *rest = str;
    
    while((token = strtok_r(rest, " ", &rest))) {
        strcpy(c[possible_words], token);
        token = strtok(str, " ");
        plog(c[possible_words]);
        if (search(c[possible_words])) {
            words++;
        }
        possible_words++;
    }
    if(possible_words == 0)
        return 0.0;
    
    return words / possible_words;
}

int search(char word[]) {
    // To Store Current Word
    char c[100];
    
    // Points to current location in words.txt
    FILE *fptr;
    
    // New-Line-delimited .txt Dictionary
    if ((fptr = fopen("words.txt", "r")) == NULL)
    {
        printf("Error! opening file\n");
        // Program exits if file pointer returns NULL.
        exit(1);
    }
    
    int max = 500000;
    char ccs[max][100];
    // Reads text until newline
    int i = 0;
    while (fscanf(fptr, "%s", c) != EOF && i < max) {
        if (strcasecmp(word, c) == 0) {
            fclose(fptr);
            return 1;
        }
        //Copy c contents to a new string
        if (i == max - 1)
            printf("Data from the file: %s\n", c);
        i++;
    }
    fclose(fptr);
    return 0;
}

void sorting(struct probableMessage* pm, int SIZE, FILE* out) {

    heapsort(pm, SIZE, sizeof(struct probableMessage), (int(*)(const void*, const void*))comparator);

    
    int k;
    for (k = 0; k < (int)(.4 * SIZE); k++) {
        if(pm[k].probability > .01){ //uncertain double comparison is ok, our purpose is that P is above 0
            char * msg = "";
            asprintf(&msg,"%d: %f:\n\t%s\n", k, pm[k].probability, pm[k].message);
            plog(msg);
        
            //output the probabilistically sorted messages to the output file
            fputs(msg, out);
        }
        free(pm[k].message);
        fflush(out);
       
    }
    
    
    
    fclose(out);
}

int comparator(const void* p, const void* q){
    
    struct probableMessage a = *((struct probableMessage*) p);
    struct probableMessage b = *((struct probableMessage*) q);
    
    return ((int)((b.probability)*100)) - ((int)((a.probability)*100));
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

void plog(char *output) {
    if (logging) {
        printf("%s\n", output);
        fflush(stdout);
    }
}

