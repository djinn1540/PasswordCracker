//encryption format from the openssl wiki
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
//#include <omp.h>

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

struct probableMessage* results;

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
            printf("your index is %d\n", num);
            fflush(stdout);
            
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
            out_buf[0] = '\0';
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
        out_buf[0] = '\0';
        EVP_CIPHER_CTX_cleanup(ctx);
        //cleanup(params, ifp, ofp, ERR_EVP_CIPHER_FINAL);
    }
        //this is where we write to the file that is read into the buffer we want to tokenize
    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    if(params->encrypt == 0){
        printf("%s",out_buf);
        fflush(stdout);
    }
    
    
    if (ferror(ofp)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        //cleanup(params, ifp, ofp, errno);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}


int main(int argc, char *argv[]) {
    FILE *f_input, *f_enc, *f_dec,*outfile;
    
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
    
    
    
    int const KEYSPACESIZE = 10;
    results = (struct probableMessage*)malloc(sizeof(struct probableMessage)*KEYSPACESIZE);
    
    fflush(stdout);
    
    //here is where we insert our loop for key iteration
<<<<<<< HEAD
//#pragma omp parallel for
    for(int i = 0; i < KEYSPACESIZE; i++){
        
        /* Open the encrypted file for reading in binary ("rb" mode) */
        FILE* f_input2 = fopen("encrypted_file", "rb");
        if (!f_input2) {
            /* Unable to open file for reading */
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
            return errno;
        }
=======
    for(int i = 0; i < 10; i++) {
>>>>>>> 4053238f9e30f7536d0947b08d46ea85e7c3a67e
    
        //make a guessed key based on the iteration index of the loop
        unsigned char* guessedKey[AES_256_KEY_SIZE];
        char* temp;
        temp = (char*)malloc(sizeof(char)*AES_256_KEY_SIZE);
        insertNum(i, temp, AES_256_KEY_SIZE); // the int is the number in the key that will be prepended with 0's todo change 1-> i
       // printf("%s", temp);
       // fflush(stdout);
        printf("fools!");
        fflush(stdout);
        memcpy(key, temp, AES_256_KEY_SIZE);
        printf("%s", key);
        fflush(stdout);
        free(temp);
        
        //alter params with the guessed key
        params->key = key;
        //keep the iv the same bc Kerckhoffs's principle say the attacker can know all except the key
    
        
        
        char* decrypted_phrase;
        char filename[36];
        sprintf(filename, "decry%d", i);
        printf("%s",filename);
        fflush(stdout);
        outfile = fopen(filename, "wb");
        if (!outfile) {
            /* Unable to open file for writing */
            fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
            return errno;
        }
        
        /* Decrypt the given file */
        file_encrypt_decrypt(params, f_input2, outfile); //f_dec instead of decrypted_phrase to print to file
        //read_chars_from_file(decrypted_phrase, )
        fclose(outfile);
        
        double percent = countProbEnglWords(decrypted_phrase);
        struct probableMessage currentMessage;
        currentMessage.message = decrypted_phrase;
        currentMessage.probability = percent;
        
        results[i] = currentMessage;
        fclose(f_input2);
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

<<<<<<< HEAD
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
        if (search(c[possible_words])) {
            printf("A WORD!: %s\n", c[possible_words]);
            words++;
        }
        possible_words++;
    }
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
    printf("About to sort!\n");
    heapsort(pm, SIZE, sizeof(struct probableMessage), (int(*)(const void*, const void*))comparator);
    printf("Just sorted!\n");
    
    int k;
    for (k = 0; k < 5; k++) {
        char * msg = "";
        asprintf(&msg,"%d: %f:\n\t%s\n", k, pm[k].probability, pm[k].message);
        printf("%s", msg);
        
        //output the probabilistically sorted messages to the output file
        fputs(msg, out);
    }
    
    
    
    fclose(out);
}

int comparator(const void* p, const void* q){
    
    struct probableMessage a = *((struct probableMessage*) p);
    struct probableMessage b = *((struct probableMessage*) q);
    
    return ((int)((b.probability)*100)) - ((int)((a.probability)*100));
}

=======
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
>>>>>>> 4053238f9e30f7536d0947b08d46ea85e7c3a67e
