#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);


    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror("Connection failed");
        abort();
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     * 2. Create a new TLS client context (TLS_client_method)
     * 3. Load CA certificate to verify server
     * 4. Configure SSL_CTX to verify server certificate
     */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();               /* (Old OpenSSL) Boot the SSL library */
    OpenSSL_add_all_algorithms();     /* (Old) Register crypto algorithms */
    SSL_load_error_strings();         /* (Old) Human-readable error messages */
#endif

    const SSL_METHOD *method = TLS_client_method(); /* Generic client method */
    SSL_CTX *ctx = SSL_CTX_new(method);             /* Create client TLS context */

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Trust store: CA that signed the SERVER certificate (so we can verify it) */
    if (SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL) != 1) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Verify the server’s cert during handshake (fail if untrusted) */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 4);

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* TODO:
     * 1. Load client certificate using SSL_CTX_use_certificate_file
     * 2. Load client private key using SSL_CTX_use_PrivateKey_file
     * 3. Verify that private key matches certificate using SSL_CTX_check_private_key
     */

    /* Client public certificate (identity) */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Client private key (matches the public key inside the certificate) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    /* Sanity check: cert/key pair must match */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Client private key does not match the certificate\n");
        abort();
    }
}


int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(0);
    }

    char *hostname = argv[1];
    int port = atoi(argv[2]);
    SSL_CTX *ctx;
    SSL *ssl;
    int server;

    /* TODO:
     * 1. Initialize SSL context using InitCTX
     * 2. Load client certificate and key using LoadCertificates
     */
    ctx = InitCTX();                                  /* 1) Build client TLS context */
    LoadCertificates(ctx, "client.crt", "client.key");/* 2) Load client cert/key for mTLS */

    server = OpenConnection(hostname, port);          /* TCP connect */
    ssl = SSL_new(ctx);                               /* Per-connection TLS object */
    SSL_set_fd(ssl, server);                          /* Bind the socket to TLS */

    /* TODO:
     * 1. Establish SSL connection using SSL_connect
     * 2. Ask user to enter username and password
     * 3. Build XML message dynamically
     * 4. Send XML message over SSL
     * 5. Read server response and print it
     */
    if (SSL_connect(ssl) == FAIL) {                   /* 1) TLS handshake (client side) */
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(server);
        SSL_CTX_free(ctx);
        return 1;
    }

    /* 2) Prompt for credentials */
    char username[64], password[64];
    printf("Enter username: "); fflush(stdout);
    if (scanf("%63s", username) != 1) strcpy(username, "");
    printf("Enter password: "); fflush(stdout);
    if (scanf("%63s", password) != 1) strcpy(password, "");

    /* 3) Build XML message */
    char msg[256];
    snprintf(msg, sizeof(msg),
             "<Body><UserName>%s</UserName><Password>%s</Password></Body>",
             username, password);

    /* 4) Send over TLS */
    if (SSL_write(ssl, msg, (int)strlen(msg)) <= 0) {
        ERR_print_errors_fp(stderr);
    }

    /* 5) Read server response */
    char buf[512] = {0};
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        printf("Server reply: %s\n", buf);
    } else if (n < 0) {
        ERR_print_errors_fp(stderr);
    }

    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
