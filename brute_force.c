#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

//global output filename
FILE* output;

int decrypt(unsigned char* ciphertext, int ciphertextLength, unsigned char* key,
            unsigned char* initvector, unsigned char* plaintext);
double countProbEnglWords(char str[]);
int search(char word[]);
void sorting();

int main (void){
    
    //initialize output file to blank
    FILE* cipherfile = fopen("cipher.txt", "rb");
    if (cipherfile == NULL){
        printf("cipher.txt was not found, make sure it is initialized");
        return 0;
    }
    
    //read in the ciphertext from file
    fseek(cipherfile, 0L, SEEK_END); //to find the size of the file
    int const CIPHERTEXT_SIZE = ftell(cipherfile); //sizeof ciphertext in the file
    rewind(cipherfile); //puts the file cursor back to the beginning of the file
    
    unsigned char ciphertext[CIPHERTEXT_SIZE];
    unsigned char decryptedText[CIPHERTEXT_SIZE + 1];
    
    int size = fread(ciphertext,sizeof(unsigned char),CIPHERTEXT_SIZE,cipherfile);
    if(size != CIPHERTEXT_SIZE){
        printf("Reading error while trying to read from cipherfile");
    }
    
    output = fopen("output.txt", "w");
    
    //threadBody(ciphertext, CIPHERTEXT_SIZE, decryptedText);
    //loop through its (the thread's) portion of the keyspace
    for(int i = 0; i < 10; i++){
        int decryptedTextLength;
        
        
        //use keys 000...00-000...09 for 256 bit key (32 characters)
       /* int keynum = i;
        int keyindex = 31;
        unsigned char* currentKey[32] = (unsigned char*) "00000000000000000000000000000000";
        while (keynum > 0){
            currentKey[keyindex] = (unsigned char)(keynum % 10);
            keynum = (int) (keynum / 10);
            keyindex--;
        }
        printf("%c", currentKey[31]); */
        
        unsigned char* currentKey = (unsigned char*) "00000000000000000000000000000001";
        unsigned char* initvector = (unsigned char*) "0000000000000001";
        
        //decrypt the ciphertext with the current key
        decryptedTextLength = decrypt(ciphertext, CIPHERTEXT_SIZE, currentKey, initvector, decryptedText); //iv will be known, this is for simplicity
        
        
        //make sure the resulting plaintext is in ASCII (or convert it)
        //decryptedText[decryptedTextLength] = '\0'; //to make it printable
        //printf("%s\n", decryptedText);
        
        
        //test against words of interest (if fails to output it, test against tokenizing)
        //tokenize the plaintext on " " and test the token against an english dictionary file
        //if it gets > 20% english tokens or numbers, print it to the output file
        
    }
    return 0;
}

int decrypt(unsigned char* ciphertext, int ciphertextLength, unsigned char* key,
            unsigned char* initvector, unsigned char* plaintext){
    EVP_CIPHER_CTX *ctx;
    
    int length;
    
    int plaintextLength;
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("failed to initialize decryption context\n");
        return -1;
    }
    
    //initialize the decryption operation
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, initvector)){
        printf("decryption scheme initialization has failed\n");
        return -1;
    }
    
    // do the actual decryption of the ciphertext
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertextLength)){
        printf("decryption of the ciphertext has failed");
        return -1;
    }
    plaintextLength = length;
    printf("%s",plaintext);
    
    //finalization of decryption - may add more plaintext
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + length, &length)) {
        printf("decryption finalization has failed. OpenSSL error: %s\n",
               ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }
    plaintextLength += length;
    
    // Clean up decryption environment
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintextLength;
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

void sorting() {
    const int SIZE = 50;
    int ints[SIZE];
    int j;
    for (j = 0; j < SIZE; j++) {
        ints[j] = rand();
    }
    
    heapsort(ints, SIZE, sizeof(int), (int(*)(const void*, const void*))comparator);
    
    int i;
    
    for (i = 0; i < SIZE; i++) {
        printf("%d\n", ints[i]);
    }
}


