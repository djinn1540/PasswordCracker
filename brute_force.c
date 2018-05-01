#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <omp.h>

//global output filename
FILE* output;

struct probableMessage {
    double probability;
    char* message;
};

int decrypt(unsigned char* ciphertext, int ciphertextLength, unsigned char* key,
            unsigned char* initvector, unsigned char* plaintext);
char *readMessageFromFile(FILE *out);
double countProbEnglWords(char str[]);
int search(char word[]);
void sorting(struct probableMessage* pm, int SIZE, FILE* out);
int comparator(const void* p, const void* q);

struct probableMessage* results;

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

    int size = fread(ciphertext,sizeof(unsigned char),CIPHERTEXT_SIZE,cipherfile);
    if(size != CIPHERTEXT_SIZE){
        printf("Reading error while trying to read from cipherfile");
    }
    fclose(cipherfile);

    output = fopen("output.txt", "w");
    
    int KEYSPACE = 5;
    results = malloc(sizeof(struct probableMessage)*KEYSPACE);
    
//    threadBody(ciphertext, CIPHERTEXT_SIZE, decryptedText);
    //loop through its (the thread's) portion of the keyspace
    #pragma omp parallel for
    for(int i = 0; i < 5; i++){
        int decryptedTextLength;
        
            unsigned char decryptedText[CIPHERTEXT_SIZE + 1];
//        unsigned char decryptedText[100];
        unsigned char *decryption;
        
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
//        if (i == 0) {
//            decryption = "I am a message";
//        }
//        if (i == 1) {
//            decryption = "I amnt message";
//        }
//        if (i == 2) {
//            decryption = "Imaybe message";
//        }
//        if (i == 3) {
//            decryption = "I message?";
//        }
//        if (i == 4) {
//            decryption = "Iwamfadwsde messffegage";
//        }
//
        decryption = decryptedText;
        
        struct probableMessage thisMessage;
        thisMessage.message = decryption;
        printf("\nbefore: %s\n", thisMessage.message);
        strcpy(decryptedText, decryption);
        double probable = countProbEnglWords(decryptedText);
        thisMessage.probability = probable;
        printf("after: %s\n", thisMessage.message);
        
        
        printf("%f\n", probable);
        
        results[i] = thisMessage;
        int k = 0;
        for (k = 0; k <= i; k++) {
            printf("RESULT %i: %s\n", i, results[k]);
        }
    }

    sorting(results, KEYSPACE, output);
    
    
    
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
    
    //finalization of decryption - may add more plaintext
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + length, &length)) {
        printf("pretend this part of the decryption worked\n");
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


