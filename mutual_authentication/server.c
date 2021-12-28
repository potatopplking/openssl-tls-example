#include <sys/socket.h>
#include <arpa/inet.h>
//#include <openssl/applink.c>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 6666

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
    struct sockaddr_in serv_addr, cli_addr;
    int sockfd, newsockfd, ssl_err;
    unsigned int clilen;
    SSL_CTX *sslctx;
    SSL *cSSL;

    InitSSL();
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (0 > sockfd) {
        return -1;
    }
    memset((void *)&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    // if (1 != inet_pton(AF_INET, SERVER_ADDR, &(addr.sin_addr.s_addr))) {
    //     fprintf(stderr, "Error: inet_pton() failed\n");
    //     return -2;
    // }
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(SERVER_PORT);
    
    if (0 != bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) {
        fprintf(stderr, "Error: bind() failed\n");
        return -3;
    }
    /* interesting stuff (SSL) starts here */
    sslctx = SSL_CTX_new(TLS_server_method());
    /* add CA cert for checking server cert */
    if (SSL_FAIL(SSL_CTX_load_verify_locations(sslctx, "cert/cacert.pem", NULL))) {
        fprintf(stderr, "SSL_CTX_load_verify_locations() failed\n");
        return -4;
    }
    SSL_CTX_set_verify(sslctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    //SSL_CTX_set_options(sslctx, SSL_OP_SINGLE_DH_USE); // needed?
    if (SSL_FAIL(SSL_CTX_use_certificate_file(sslctx, "cert/servercert.pem", SSL_FILETYPE_PEM))) {
        fprintf(stderr, "SSL_CTX_use_certificate_file() failed\n");
        return -6;
    }
    if (SSL_FAIL(SSL_CTX_use_PrivateKey_file(sslctx, "cert/serverkey.pem", SSL_FILETYPE_PEM))) {
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file() failed\n");
        return -7;
    }

    listen(sockfd, 5);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    cSSL = SSL_new(sslctx);
    SSL_set_fd(cSSL, newsockfd);
    ssl_err = SSL_accept(cSSL);
    if (ssl_err <= 0) {
        ssl_err = SSL_get_error(cSSL, ssl_err);
        int err = ERR_get_error();
        fprintf(stderr, "SSL_accept() error: %s\n", ERR_error_string(err, NULL));
        ShutdownSSL(cSSL);
        return -4;
    }

    #define BUFLEN 1024
    char buffer[BUFLEN];
    int n = SSL_read(cSSL, buffer, BUFLEN);
    printf("Server received %d bytes: %s\n", n, buffer);

    const char msg[] = "Hello back to you!";
    SSL_write(cSSL, msg, sizeof(msg) / sizeof(char));

    ShutdownSSL(cSSL);
    return 0;
}