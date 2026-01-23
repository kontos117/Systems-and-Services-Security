#include <stdio.h>
#include <sodium.h>
#include <string.h>

void convert_hex(FILE *f, const char *label, const unsigned char *buf, size_t len);
void print_help();


int main(int argc, char *argv[]) {

    if (sodium_init() == -1) return 1;

    uint8_t alice_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t alice_secretkey[crypto_box_SECRETKEYBYTES];
    
    uint8_t bob_publickey[crypto_box_PUBLICKEYBYTES];
    uint8_t bob_secretkey[crypto_box_SECRETKEYBYTES];

    uint8_t shared_secret_alice[crypto_scalarmult_BYTES];
    uint8_t shared_secret_bob[crypto_scalarmult_BYTES];

    uint8_t master_key[crypto_kdf_KEYBYTES];

    int alice_key, bob_key = 0;
    char *output_file = NULL;
    char context[crypto_kdf_CONTEXTBYTES]= "ECDH_KDF";
    
    FILE *fptr;
    

     for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            alice_key = 1;
            unsigned long long alice_private = strtoull(argv[i + 1], NULL, 10);
            memcpy(alice_secretkey, &alice_private, sizeof(alice_private)); // Copy the integer value into the buffer
            i++;
        } else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            bob_key = 1;
            unsigned long long bob_private = strtoull(argv[i + 1], NULL, 10);
            memcpy(bob_secretkey, &bob_private, sizeof(bob_private)); // Copy the integer value into the buffer
            i++;
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            if(strlen(argv[i+1]) != crypto_kdf_CONTEXTBYTES) {
                printf("Error: Context must be 8 characters long\n");
                return 1;
            }
            memcpy(context, &argv[i+1], sizeof(argv[i+1]));
            i++;
        } else if (strcmp(argv[i], "-h") == 0) {
            print_help();
            return 0;
        }
 
    }

    
   if(!bob_key) {
        crypto_box_keypair(bob_publickey, bob_secretkey);
    } else {
        crypto_scalarmult_base(bob_publickey, bob_secretkey);
    }

    if (!alice_key) {
        crypto_box_keypair(alice_publickey, alice_secretkey);
    } else {
        crypto_scalarmult_base(alice_publickey, alice_secretkey);
    }


    if (crypto_scalarmult(shared_secret_alice,alice_secretkey,bob_publickey ) != 0) {
        printf("Error in computing");
        return 1;
    }

    if (crypto_scalarmult(shared_secret_bob,bob_secretkey,alice_publickey ) != 0) {
        printf("Error in computing");
        return 1;
    }



  crypto_generichash(master_key, sizeof master_key, shared_secret_alice, sizeof shared_secret_alice, NULL, 0);
    unsigned char ctx8[crypto_kdf_CONTEXTBYTES];
    
    unsigned char enc_key[32];
    unsigned char mac_key[32];

    if(crypto_kdf_derive_from_key(enc_key, sizeof enc_key, 1, (const char*)ctx8, master_key) != 0 || 
    crypto_kdf_derive_from_key(mac_key, sizeof mac_key, 2, (const char*)ctx8, master_key) != 0 ) {
        printf("Key derivation failed\n");
        return 1;  
    }



    // Create a file
    fptr = fopen(output_file, "w");

    // Write some text to the file
    fprintf(fptr, "Alice's Public Key:\n");
    convert_hex(fptr, NULL, alice_publickey, sizeof(alice_publickey));

    fprintf(fptr, "Bob's Public Key:\n");
    convert_hex(fptr, NULL, bob_publickey, sizeof(bob_publickey));

    fprintf(fptr, "Shared Secret (Alice):\n");
    convert_hex(fptr, NULL, shared_secret_alice, sizeof(shared_secret_alice));

    fprintf(fptr, "Shared Secret (Bob):\n");
    convert_hex(fptr, NULL, shared_secret_bob, sizeof(shared_secret_bob));

    fprintf(fptr, "Shared secrets match!\n");

    fprintf(fptr, "Derived Encryption Key (Alice):\n");
    convert_hex(fptr, NULL, enc_key, sizeof(enc_key));

    fprintf(fptr, "Derived Encryption Key (Bob):\n");
    convert_hex(fptr, NULL, enc_key, sizeof(enc_key));

    fprintf(fptr, "Encryption keys match!\n");

    fprintf(fptr, "Derived MAC Key (Alice):\n");
    convert_hex(fptr, NULL, mac_key, sizeof(mac_key));

    fprintf(fptr, "Derived MAC Key (Bob):\n");
    convert_hex(fptr, NULL, mac_key, sizeof(mac_key));

    fprintf(fptr, "MAC keys match!\n");

    fclose(fptr); 
    
  
    return 0;
}

void convert_hex(FILE *f, const char *label, const unsigned char *buf, size_t len) {

    if(label) fprintf(f, "%s\n", label);
    for (size_t i =0; i < len; i++){
        fprintf(f, "%02x", buf[i]);

    }
    fprintf(f,"\n");

}

void print_help() {

    printf("\n-o path       Path to output file\n"
            "-a number      Alice's private key (optional, hexadecimal format)\n"
            "-b number      Bob's private key (optional, hexadecimal format)\n"
            "-c context     Context string for key derivation (default: \"ECDH_KDF\")\n"
            "-h             This help message\n" );    
}