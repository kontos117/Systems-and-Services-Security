#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>

#define FAIL -1

typedef struct userData {
    char name[100];
    char password[100];
    float year;
    char BlogType[100];
    char Author[100];
} userd;

userd userArray[10] = {
        {"christaras101", "admin", 4, "Astrologia", "Yes King"},
        {"kontos117", "12345", 3.9, "tost making", "John Halo"},
        {"Sousi", "123", 1.5, "Embedede and c c++", "John Johny"}
    };


int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (!preverify_ok) {
        const char *rmessage = "peer did not return a certificate or returned an invalid one";
        // try to sent message if connection is still up
        SSL_write(ssl, rmessage, strlen(rmessage));
    }
    return preverify_ok; // return 0 if verify failed
} 

SSL_CTX* InitServerCTX(void) {
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS server context (TLS_server_method)
     * 3. Load CA certificate for client verification
     * 4. Configure SSL_CTX to require client certificate (mutual TLS)
     */

#if OPENSSL_VERSION_NUMBER < 0x10100000L
     SSL_library_init();
     OpenSSL_add_all_algorithms();
     SSL_load_error_strings();
#endif

const SSL_METHOD *method = TLS_server_method(); // Use modern TLS server method
SSL_CTX *ctx = SSL_CTX_new(method);             // Create new SSL context based on that method

// Load CA certificate that will be used to verify client certificates
if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
    ERR_print_errors_fp(stderr);
    abort();
}


// Require clients to send valid certificates (mutual TLS)
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
SSL_CTX_set_verify_depth(ctx, 4);               // Limit verification chain length

if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    abort();
}

return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    /* TODO:
     * 1. Load server certificate using SSL_CTX_use_certificate_file
     * 2. Load server private key using SSL_CTX_use_PrivateKey_file
     * 3. Check that private key matches the certificate using SSL_CTX_check_private_key
     */

    if (SSL_CTX_use_certificate_file(ctx,CertFile,SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        abort();

    }   

    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0){
        ERR_print_errors_fp(stderr);
        abort();

    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        abort();
    }

}


void ShowCerts(SSL* ssl) {
    /* TODO:
     * 1. Get client certificate (if any) using SSL_get_peer_certificate
     * 2. Print Subject and Issuer names
     */

     X509 *cert = SSL_get_peer_certificate(ssl);
     if (cert) {
         // Convert the Subject (who the cert is for) into a simple string.
         char *subj = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
         // Convert the Issuer (who signed the cert) into a simple string.
         char *iss  = X509_NAME_oneline(X509_get_issuer_name(cert),  0, 0);
 
         printf("Client certificate:\n  Subject: %s\n  Issuer : %s\n", subj, iss);
 
         OPENSSL_free(subj);                         // Free the temporary strings allocated by OpenSSL.
         OPENSSL_free(iss);
         X509_free(cert);                            // Release the certificate object.
     } else {
         printf("No client certificate presented.\n"); // Shouldn't happen if mTLS is required.
     }
}

void Servlet(SSL* ssl) {
    char buf[1024] = {0};

    if (SSL_accept(ssl) == FAIL) {                  // Complete TLS handshake
        ERR_print_errors_fp(stderr);
        return;
    } 

    ShowCerts(ssl);                                 // Print client cert info (if any)

    /* Read one application message from client (up to 1023 bytes) */
    int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        SSL_free(ssl);
        return;
    }
    buf[bytes] = '\0';
    printf("Client message: %s\n", buf);

    /* ---------- Parse XML for <UserName> and <Password> ---------- */
    char user[128] = {0}, pass[128] = {0};
    const char *u_open = "<UserName>";
    const char *u_close = "</UserName>";
    const char *p_open = "<Password>";
    const char *p_close = "</Password>";

    char *u1 = strstr(buf, u_open);
    char *u2 = strstr(buf, u_close);
    char *p1 = strstr(buf, p_open);
    char *p2 = strstr(buf, p_close);

    if (u1 && u2 && p1 && p2 && u2 > u1 && p2 > p1) {
        size_t ul = (size_t)(u2 - (u1 + strlen(u_open)));
        size_t pl = (size_t)(p2 - (p1 + strlen(p_open)));
        if (ul >= sizeof(user))  ul = sizeof(user) - 1;
        if (pl >= sizeof(pass))  pl = sizeof(pass) - 1;
        memcpy(user, u1 + strlen(u_open), ul); user[ul] = '\0';
        memcpy(pass, p1 + strlen(p_open), pl); pass[pl] = '\0';
    } else {
        /* Malformed XML — respond with FAIL and close */
        const char *bad = 
                "<Response>\n"
                "   <Status>FAIL</Status>"
                "   <Reason>BadXML</Reason>"
                "</Response>";
        SSL_write(ssl, bad, (int)strlen(bad));
        int sd_bad = SSL_get_fd(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sd_bad);
        return;
    }

    /* ---------- Check credentials ---------- */
    int saveIndex;
    int ok = 0;

    for(int i = 0; i < sizeof(userArray) / sizeof(userArray[0]); i++) {
        ok = (strcmp(user, userArray[i].name) == 0 && strcmp(pass, userArray[i].password) == 0);
        if(ok) {
            saveIndex = i;
            break;
        }
    }

    for (int i = 0; i < strlen(userArray[saveIndex].name); i++) {
        userArray[saveIndex].name[i] = tolower(userArray[saveIndex].name[i]);
    }

    //const char *ok_user = "sousi";
    //const char *ok_pass = "123";
    //int ok = (strcmp(user, ok_user) == 0 && strcmp(pass, ok_pass) == 0);

    /* ---------- Build and send XML response ---------- */
    if (ok) {
        char reply[1000];
        snprintf(reply, sizeof(reply),
            "\n<Body>\n"
            "     <Name>%s.com</Name>\n"
            "     <year>%.1f</year>\n"
            "     <BlogType>%s</BlogType>\n"
            "     <Author>%s</Author>\n"
            "</Body>\n",
            userArray[saveIndex].name,
            userArray[saveIndex].year,
            userArray[saveIndex].BlogType,
            userArray[saveIndex].Author);

        SSL_write(ssl, reply, (int)strlen(reply));
    } else {
        const char *invalid = "Invalid Message";
        SSL_write(ssl, invalid, (int)strlen(invalid));
    }

    /* ---------- Clean shutdown ---------- */
    int sd = SSL_get_fd(ssl);
    SSL_shutdown(ssl);                               // Send/receive close_notify
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    

    int port = atoi(argv[1]);
    SSL_CTX *ctx;

    /* TODO:
     * 1. Initialize SSL context using InitServerCTX
     * 2. Load server certificate and key using LoadCertificates
     */
    ctx = InitServerCTX();                          // 1) build TLS server context (requires client certs, trusts ca.crt)
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    LoadCertificates(ctx, "server.crt", "server.key"); // 2) load this server's cert + private key

    int server = OpenListener(port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("accept");
            continue;
        }
        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* TODO:
         * 1. Create new SSL object from ctx
         * 2. Set file descriptor for SSL using SSL_set_fd
         * 3. Call Servlet to handle the client
         */
        ssl = SSL_new(ctx);                         // 1) per-connection TLS object
        if (!ssl) {
            ERR_print_errors_fp(stderr);
            close(client);
            continue;
        }

        SSL_set_fd(ssl, client);                    // 2) attach the accepted TCP socket to TLS

        Servlet(ssl);                               // 3) do handshake, read/write, and clean up
        // (Servlet() calls SSL_free(ssl) and closes the socket)
    }

    close(server);
    SSL_CTX_free(ctx);
}
