#include <stdio.h>
#include <gmp.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>

int generate_rsa_keys(int key_length);
void encryptRSA(char*plaintext, char *ciphertext, char*publicKey);
void decryptRSA(char *decrypted, char *ciphertext, char *privateKey);
void sign_rsa(char *input_file, char *output_file, char *privatekey);
void verifyRSA(char *plaintext, char *publicKey, char *signatureFile);
void run_test(int key_length, char * file);
void print_help();


int main(int argc, char *argv[]) {

    char *input_file = NULL;
    char *output_file = NULL;
    char *key_file = NULL;
    char *pfile = NULL;
    char *signature_output = NULL;
    int key_length;
    int key_lengths_arr[3] = {1024, 2048, 4096};

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            input_file = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
            key_file = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-g") == 0 && i + 1 < argc) {
            key_length = atoi(argv[i + 1]);
            generate_rsa_keys(key_length);
            i++;
        } else if (strcmp(argv[i], "-d") == 0) {
            decryptRSA(output_file, input_file, key_file);
        } else if (strcmp(argv[i], "-e") == 0) {
           encryptRSA(input_file, output_file, key_file);
        } else if (strcmp(argv[i], "-s") == 0) {
           sign_rsa(input_file, output_file, key_file);
           
        } else if (strcmp(argv[i], "-v") == 0 && i + 1 < argc) {
            signature_output = argv[i + 1];
            verifyRSA(input_file, key_file, signature_output);
            i++;
        } else if (strcmp(argv[i], "-a") == 0) {
            pfile = argv[i + 1];
            int count = sizeof(key_lengths_arr)/sizeof(key_lengths_arr[0]);
            for(int i = 0; i < count; i++) {
                run_test(key_lengths_arr[i], pfile);
            }
        } else if (strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        }
    }

    return 0;
}


int generate_rsa_keys(int key_length) {

    /* generate p and q */

    mpz_t p, q, n, lambda_n, d, e, q_1, p_1,temp;
    gmp_randstate_t state;

   
    mpz_inits(p, q, n, lambda_n, d,e,q_1, p_1,temp, NULL); 
    mpz_set_ui(e, 65537);

   int l1=0,l2=0;

   
    gmp_randinit_default (state);
    
    

    mpz_rrandomb(p, state, key_length/2);
    mpz_nextprime(p, p);
    mpz_rrandomb(q, state, key_length/2);
    mpz_nextprime(q, q);

    
    while (!l1||!l2){
       
        if(!l1) {
            mpz_rrandomb(p, state, key_length/2);
            mpz_nextprime(p, p);
            if(mpz_probab_prime_p (p, 30) != 0)
            l1=1;
            
        }
            
        if(!l2){
            mpz_rrandomb(q, state, key_length/2);
            mpz_nextprime(q, q);
            if(mpz_probab_prime_p (q, 30) != 0)
            l2=1;    
        }

    }
   
    mpz_mul(n,p,q);
    mpz_sub_ui(p_1, p, 1);  // p - 1
    mpz_sub_ui(q_1, q, 1);  // q - 1
    mpz_mul(lambda_n, p_1, q_1);

   
   mpz_gcd(temp, e, lambda_n);
   if(mpz_cmp_d(temp, 1)) exit(1);

   mpz_invert (d, e, lambda_n);
    
    char filename1[50];
    char filename2[50];
  
    // Step 6: Write public key (n, e)
    FILE * publicKeyFile;
    sprintf(filename1, "public_%d.key", key_length);
    publicKeyFile = fopen(filename1, "w");
    if (publicKeyFile == NULL) {
        perror("Failed to open public key file");
        mpz_clears(p, q, n, lambda_n, e, d, temp,q_1, p_1 ,temp, NULL);
        exit(1);
    }
    // Write n and e as hexadecimal
    
    gmp_fprintf(publicKeyFile, "%Zx,%Zx\n", n, e);
    fclose(publicKeyFile);

    // Step 7: Write private key (n, d)
    FILE * privateKeyFile;
    sprintf(filename2, "private_%d.key", key_length);
    privateKeyFile = fopen(filename2, "w");
    if (privateKeyFile == NULL) {
        perror("Failed to open private key file");
        mpz_clears(p, q, n, lambda_n, e, d, temp,q_1, p_1 ,temp, NULL);
        exit(1);
    }
    // Write n and d as hexadecimal
    gmp_fprintf(privateKeyFile, "%Zx,%Zx\n", n, d);
    fclose(privateKeyFile); 
    
    // Step 8: Output the public key (n, e) and private key (n, d)
    // gmp_printf("Public Key (n, e): \nn = %Zd\ne = %Zd\n", n, e);
    // gmp_printf("Private Key (n, d): \nn = %Zd\nd = %Zd\n", n, d);

    
    // Clear memory

    mpz_clears(p, q, n, lambda_n, e, d,q_1, p_1 ,temp, NULL);

    return 0;
}

void encryptRSA(char *plaintext, char *ciphertext, char*publicKey) {

    FILE *plaintextFile = NULL;
    FILE *ciphertextFile = NULL;
    FILE *publicKeyFile = NULL;

    mpz_t n,e,m,c;

    mpz_inits(n,e,m,c, NULL);

    plaintextFile = fopen(plaintext, "rb");
    ciphertextFile = fopen(ciphertext, "wb");
    publicKeyFile = fopen(publicKey, "r");

    if(!plaintextFile || !ciphertextFile || !publicKeyFile){
        perror("encryptRSA failed to open file");
        if (plaintextFile)  fclose(plaintextFile);
        if (ciphertextFile) fclose(ciphertextFile);
        if (publicKeyFile)  fclose(publicKeyFile);
        return;

    }

    if(gmp_fscanf(publicKeyFile, "%Zx,%Zx", n, e) != 2) {
        fprintf(stderr, "encryptRSA: could not read public key\n");
        fclose(plaintextFile);
        fclose(ciphertextFile);
        fclose(publicKeyFile);
        mpz_clears(n,e,m,c);
        return;
    }

    fclose(publicKeyFile);

    size_t n_bits = mpz_sizeinbase(n,2);
    size_t n_bytes = (n_bits + 7) / 8;
  
    if (n_bytes == 0){
        fprintf(stderr, "encryptRSA, invalid modulus size \n");
        fclose(plaintextFile);
        fclose(ciphertextFile);
        mpz_clears(n,e,m,c,NULL);
        return;
    
    }
    
    size_t plain_block_size = n_bytes -1;
    if(plain_block_size == 0){    
        fprintf(stderr, "encryptRSA, block size too small \n");
        fclose(plaintextFile);
        fclose(ciphertextFile);
        mpz_clears(n,e,m,c, NULL);
        exit(1);
    }

    unsigned char *plain_buf = malloc(plain_block_size);
    unsigned char *cipher_buf = malloc(n_bytes);
    if(!plain_buf || !cipher_buf){
        perror("encryptRSA, malloc failled");
        fclose(plaintextFile);
        fclose(ciphertextFile);
        mpz_clears(n,e, NULL);
        free(plain_buf);
        free(cipher_buf);
        return;    
    }
    
    while(1) {

    size_t bytes_read = fread(plain_buf, 1, plain_block_size, plaintextFile);
        if (bytes_read == 0) {
            if (ferror(plaintextFile)) {
                perror("encryptRSA: fread failed");
            }
            break;  
    }
    

    
     mpz_import(m, bytes_read, 1, 1, 0, 0, plain_buf);
     if (mpz_cmp(m, n) >= 0) {
            fprintf(stderr, "encryptRSA, plaintext block >= modulus, something is wrong\n");
            free(plain_buf);
            free(cipher_buf);
            fclose(plaintextFile);
            fclose(ciphertextFile);
            mpz_clears(n, e, m, c, NULL);
            exit(1);
        }
 
    mpz_powm(c, m, e, n);

        // zero-out cipher buffer and export c into the rightmost bytes
        memset(cipher_buf, 0, n_bytes);

        size_t written_words = 0;
        size_t c_bytes = (mpz_sizeinbase(c, 2) + 7) / 8;

        mpz_export(cipher_buf + (n_bytes - c_bytes),&written_words,1,  1,  0,  0,  c);

        if (fwrite(cipher_buf, 1, n_bytes, ciphertextFile) != n_bytes) {
            perror("encryptRSA: fwrite failed");
            free(plain_buf);
            free(cipher_buf);
            fclose(plaintextFile);
            fclose(ciphertextFile);
            mpz_clears(n, e, m, c, NULL);
            return;
        }
        
    }
    free(plain_buf);
    free(cipher_buf);
    fclose(plaintextFile);
    fclose(ciphertextFile);
    mpz_clears(n, e, m, c, NULL);
    
}


void decryptRSA(char *plaintext, char *ciphertext, char *privateKey) {

    FILE *plaintextFile  = NULL;
    FILE *ciphertextFile = NULL;
    FILE *privateKeyFile = NULL;

    mpz_t n, d, c, m;
    mpz_inits(n, d, c, m, NULL);

    // open files
    plaintextFile  = fopen(plaintext,  "wb");  // write decrypted bytes
    ciphertextFile = fopen(ciphertext, "rb");  // read encrypted blocks
    privateKeyFile = fopen(privateKey, "r");   // read n,d in hex

    if (!plaintextFile || !ciphertextFile || !privateKeyFile) {
        perror("decryptRSA: failed to open file");
        if (plaintextFile)  fclose(plaintextFile);
        if (ciphertextFile) fclose(ciphertextFile);
        if (privateKeyFile) fclose(privateKeyFile);
        mpz_clears(n, d, c, m, NULL);
        exit(1);
    }

    if (gmp_fscanf(privateKeyFile, "%Zx,%Zx", n, d) != 2) {
        fprintf(stderr, "decryptRSA: could not read private key\n");
        fclose(plaintextFile);
        fclose(ciphertextFile);
        fclose(privateKeyFile);
        mpz_clears(n, d, c, m, NULL);
        exit(1);
    }
    
    fclose(privateKeyFile);
    privateKeyFile = NULL;
    // determine block size from modulus
    size_t n_bits  = mpz_sizeinbase(n, 2);
    size_t n_bytes = (n_bits + 7) / 8;
    if (n_bytes == 0) {
        fprintf(stderr, "decryptRSA: invalid modulus size\n");
        fclose(plaintextFile);
        fclose(ciphertextFile);
        mpz_clears(n, d, c, m, NULL);
        return;
    }

    unsigned char *cipher_buf = malloc(n_bytes);
    unsigned char *plain_buf  = NULL;  // will allocate per block
    if (!cipher_buf) {
        perror("decryptRSA: malloc failed");
        fclose(plaintextFile);
        fclose(ciphertextFile);
        mpz_clears(n, d, c, m, NULL);
        exit(1);
    }
  
    // read ciphertext in fixed-size blocks of n_bytes
    while(1) {
        size_t bytes_read = fread(cipher_buf, 1, n_bytes, ciphertextFile);
        if (bytes_read == 0) {
            if (ferror(ciphertextFile)) {
                perror("decryptRSA: fread failed");
            }
            break;  // EOF
        }

        if (bytes_read != n_bytes) {
            // partial block – something is inconsistent with encryption format
            fprintf(stderr, "decryptRSA: partial ciphertext block (%zu bytes)\n", bytes_read);
            free(cipher_buf);
            fclose(plaintextFile);
            fclose(ciphertextFile);
            mpz_clears(n, d, c, m, NULL);
            exit(1);
        }

        // import ciphertext block into big integer c
        mpz_import(c,bytes_read, 1, 1, 0, 0, cipher_buf); 

        // m = c^d mod n
        mpz_powm(m, c, d, n);
   
        // export m back to bytes (plaintext block)
        size_t plain_bytes = (mpz_sizeinbase(m, 2) + 7) / 8;
        if (plain_bytes == 0) {
            // m == 0, nothing to write
            continue;
        }

        plain_buf = malloc(plain_bytes);
        if (!plain_buf) {
            perror("decryptRSA: malloc failed");
            free(cipher_buf);
            fclose(plaintextFile);
            fclose(ciphertextFile);
            mpz_clears(n, d, c, m, NULL);
            exit(1);
        }

        size_t written_words = 0;
        mpz_export(plain_buf,
                   &written_words,
                   1,  // most significant word first
                   1,  // 1 byte per word
                   0,  // native endianness
                   0,  // no nails
                   m);

        // write plaintext bytes for this block
        if (fwrite(plain_buf, 1, plain_bytes, plaintextFile) != plain_bytes) {
            perror("decryptRSA: fwrite failed");
            free(plain_buf);
            free(cipher_buf);
            fclose(plaintextFile);
            fclose(ciphertextFile);
            mpz_clears(n, d, c, m, NULL);
            exit(1);
        }

        free(plain_buf);
        plain_buf = NULL;
    }

    free(cipher_buf);
    fclose(ciphertextFile);
    fclose(plaintextFile);
    mpz_clears(n, d, c, m, NULL);
}


void sign_rsa(char *input_file, char *output_file, char *privatekey) {
    FILE *f = fopen(input_file, "rb");
    if (!f) {
        perror("fopen input");
        exit(1);
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        SHA256_Update(&ctx, buffer, bytes);
    }
    fclose(f);
   
    FILE *kf = fopen(privatekey, "r");
    if (!kf) {
        perror("fopen private key");
        exit(1);
    }


    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);


    mpz_t n, d, m, sig;
    mpz_inits(n, d, m, sig, NULL);

    gmp_fscanf(kf, "%Zx,%Zx\n", n, d);


    mpz_import(m, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    mpz_powm(sig, m, d, n);

    FILE *out = fopen(output_file, "w");
    if (!out) {
        perror("fopen output");
        exit(1);
    }
    gmp_fprintf(out, "%Zx\n", sig);
    fclose(out);

    mpz_clears(n, d, m, sig, NULL);
}

void verifyRSA(char *input_file, char *publickey_file, char *signature_file) {

  FILE *f = fopen(input_file, "rb");
    if (!f) {
        perror("fopen input");
        exit(1);
    }


    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        SHA256_Update(&ctx, buffer, bytes);
    }
    fclose(f);

    

    FILE *kf = fopen(publickey_file, "r");
    if (!kf) {
        perror("fopen public key");
        exit(1);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);

    mpz_t n, e, sig, hash_from_sig, m;
    mpz_inits(n, e, sig, hash_from_sig, m, NULL);
   
    if (gmp_fscanf(kf, "%Zx,%Zx\n", n, e) != 2) {
        fprintf(stderr, "Invalid public key format!\n");
        fclose(kf);
        mpz_clears(n, e, sig, hash_from_sig, m, NULL);
        exit(1);
    }
    fclose(kf);

   
    FILE *sf = fopen(signature_file, "r");
    if (!sf) {
        perror("fopen signature");
        mpz_clears(n, e, sig, hash_from_sig, m, NULL);
        exit(1);
    }
    if (gmp_fscanf(sf, "%Zx\n", sig) != 1) {
        fprintf(stderr, "Invalid signature format!\n");
        fclose(sf);
        mpz_clears(n, e, sig, hash_from_sig, m, NULL);
        exit(1);
    }
    fclose(sf);
    //gmp_printf("%Zx\n", sig);
    //fprintf(stderr, "%s", sig);
   
    mpz_powm(hash_from_sig, sig, e, n);


    mpz_import(m, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    gmp_printf("%Zx\n", hash_from_sig);
    gmp_printf("%Zx\n", m);
    int valid = (mpz_cmp(hash_from_sig, m) == 0);

    if (valid)
        printf("Signature is VALID\n");
    else
        printf("Signature is INVALID\n");

    mpz_clears(n, e, sig, hash_from_sig, m, NULL);


}




void run_test(int key_length, char * file) {


    FILE * pfile;      // performance file
    pfile = fopen(file,"a");
            
    struct rusage before, after;
    clock_t start, end;
    double cpu_time;
    long enc_mem, dec_mem, sign_mem, ver_mem;

    char pukey[20];
    snprintf(pukey, sizeof(pukey), "public_%d.key", key_length);

    char prkey[20];
    snprintf(prkey, sizeof(prkey), "private_%d.key", key_length);

    generate_rsa_keys(key_length);
    

    
    // Record the start time
    start = clock();

    getrusage(RUSAGE_SELF, &before);
    
    encryptRSA("plaintext.txt", "ciphertext.txt", pukey);
    getrusage(RUSAGE_SELF, &after);

    // Record the end time
    end = clock();
    
    // Calculate CPU time used
    cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;

    // Calculate memory usage time
    enc_mem =  after.ru_maxrss;
    
    // Write the execution time to the output file
 
    fprintf(pfile,"Key Length: %d bits\n", key_length);
    fprintf(pfile, "Encryption Time: %f s\n", cpu_time);

    // ---------------------------------------------------------------------

    // Record the start time
    start = clock();

    
    
    getrusage(RUSAGE_SELF, &before);
    decryptRSA("decrypted.txt", "ciphertext.txt", prkey);
    getrusage(RUSAGE_SELF, &after);

    // Record the end time
    end = clock();

    // Calculate the CPU time used
    cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;

    // Calculate memory usage time
    dec_mem =  after.ru_maxrss;
    
    // Write the execution time to the output file
    fprintf(pfile, "Decryption Time:                %f s\n", cpu_time);
    // ---------------------------------------------------------------------

    // Record the start time
    start = clock();

    getrusage(RUSAGE_SELF, &before);
    sign_rsa("plaintext.txt", "signature_output", prkey);
    getrusage(RUSAGE_SELF, &after);
    
    // Record the end time
    end = clock();
    
    // Calculate CPU time used
    cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;

    // Calculate memory usage time
    sign_mem =  after.ru_maxrss;
    
    // Write the execution time to the output file
    fprintf(pfile, "Signing Time: %f s\n", cpu_time);

    // ---------------------------------------------------------------------

    // Record the start time
    start = clock();

    getrusage(RUSAGE_SELF, &before);
    

    verifyRSA("plaintext.txt", pukey, "signature_output");
    getrusage(RUSAGE_SELF, &after);
    
    // Record the end time
    end = clock();
    
    // Calculate CPU time used
    cpu_time = ((double)(end - start)) / CLOCKS_PER_SEC;

    // Calculate memory usage time
    ver_mem =  after.ru_maxrss;
    
    // Write the execution time to the output file
   
    fprintf(pfile, "Verification Time: %f s\n", cpu_time);

    // ----------------------------------
    fprintf(pfile, "Peak Memory Usage (Encryption): %ld Bytes\n", enc_mem); 
    fprintf(pfile, "Peak Memory Usage (Decryption): %ld Bytes\n", dec_mem); 
    fprintf(pfile, "Peak Memory Usage (Signing): %ld Bytes\n", sign_mem); 
    fprintf(pfile, "Peak Memory Usage (Verification): %ld Bytes\n", ver_mem);
    fprintf(pfile, "\n*******************************************\n\n");
    
}

void print_help() {

    printf("\n-i path       Path to the input file\n"
            "-o path        Path to the output file\n"
            "-k path        Path to the key file\n"
            "-g length      Perform RSA key-pair generation given a key length \"length\"\n"
            "-d             Decrypt input and store results to output\n"
            "-e             Encrypt input and store results to output\n"
            "-s             Sign input file and store signature to output\n"
            "-v path        Verify signature (path to signature file) against input file\n"
            "-a             Performance analysis with three key lengths (1024, 2048, 4096)\n"
            "-h             This help message\n" );    
}
