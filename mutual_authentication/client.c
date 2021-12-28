#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define HOST "127.0.0.1"
#define PORT 6666


#define SSL_FAIL(arg) (1 != arg)

void InitSSL(void)
{
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
}

void DestroySSL(void)
{
    ERR_free_strings();
    EVP_cleanup();
}

void ShutdownSSL(SSL *ssl_pntr)
{
    SSL_shutdown(ssl_pntr);
    SSL_free(ssl_pntr);
}

int main(void)
{
    int sockfd, n, ssl_err;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    #define BUFLEN 256
    char buffer[BUFLEN];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (0 > sockfd) {
        fprintf(stderr, "Error: cannot create socket\n");
        return -1;
    }
    memset((void *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    if (1 != inet_pton(AF_INET, HOST, &(serv_addr.sin_addr.s_addr))) {
        fprintf(stderr, "Error: inet_pton() failed\n");
        return -2;
    }
    serv_addr.sin_port = htons(PORT);
    if (0 > connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) {
        fprintf(stderr, "Error: connect() failed\n");
        return -3;
    }

    /* SSL stuff */
    SSL_CTX *sslctx;
    SSL *cSSL;
    InitSSL();
    sslctx = SSL_CTX_new(TLS_client_method());
    /* add client certificates */
    if (SSL_FAIL(SSL_CTX_use_certificate_file(sslctx, "cert/clientcert.pem", SSL_FILETYPE_PEM))) {
        fprintf(stderr, "SSL_CTX_use_certificate_file() failed\n");
        return -4;
    }
    if (SSL_FAIL(SSL_CTX_use_PrivateKey_file(sslctx, "cert/clientkey.pem", SSL_FILETYPE_PEM))) {
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file() failed\n");
        return -5;
    }
    printf("Client certificates loaded\n");
    if (SSL_FAIL(SSL_CTX_check_private_key(sslctx))) {
        fprintf(stderr, "SSL_CTX_check_private_key() failed\n");
        return -6;
    }
    printf("Client certificates checked\n");
    /* set server certificate check policy - fail if not verified */
    SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER, NULL);
    /* add CA cert for checking servers cert (self-signed) - must come before SSL_new() */
    if (SSL_FAIL(SSL_CTX_load_verify_locations(sslctx, "cert/cacert.pem", NULL))) {
        fprintf(stderr, "SSL_CTX_load_verify_locations() failed\n");
        return -8;
    }
    printf("CA cert loaded\n");
    cSSL = SSL_new(sslctx);
    SSL_set_fd(cSSL, sockfd);
    if (-1 == SSL_connect(cSSL)) {
        int err = ERR_get_error();
        fprintf(stderr, "SSL_error() error: %s\n", ERR_error_string(err, NULL));
        return -2;
    }
    const char msg[] = "Hello, world from client!";
    n = SSL_write(cSSL, msg, sizeof(msg)/sizeof(char));
    printf("Client sent %d bytes\n", n);
    n = SSL_read(cSSL, buffer, BUFLEN);
    printf("Client received %d bytes: %s\n", n, buffer);
    SSL_shutdown(cSSL);
    return 0;
}
