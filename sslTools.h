#ifndef _SSL_H_
#define _SSL_H_

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

SSL_CTX *initialize_ctx(char *keyfile, char *password);
SSL_CTX *initialize_ctx_client(char *password);
void destroy_ctx(SSL_CTX *ctx);

// void load_dh_params(SSL_CTX *ctx,char *file) ;

int err_exit(char *string);
int berr_exit(char *string);


#endif
