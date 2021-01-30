#include "sslTools.h"
#include <openssl/err.h>

BIO *bio_err=0;
static char *pass;
static int password_cb(char *buf,int num, int rwflag,void *userdata);

static void sigpipe_handle(int x){ }

/* Print SSL errors and exit*/
int berr_exit(char *string) {
    syslog(LOG_ERR,"%s : %s",string, ERR_error_string(ERR_get_error(),NULL));
    exit(0);
  }

/*The password code is not thread safe*/
static int password_cb(char *buf,int num,
  int rwflag,void *userdata)
  {
    if(num<strlen(pass)+1)
      return(0);

    strcpy(buf,pass);
    return(strlen(pass));
  }




SSL_CTX *initialize_ctx(char *keyfile,char *password) {
    SSL_CTX *ctx;

    if(!bio_err){
      /* Global system initialization*/
      SSL_library_init();
      SSL_load_error_strings();

      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE,sigpipe_handle);

    /* Create our context*/
    ctx=SSL_CTX_new(TLS_method());

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_chain_file(ctx,
      keyfile)))
      berr_exit("Can't read certificate file");

    pass=password;
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);

    if(!(SSL_CTX_use_PrivateKey_file(ctx, keyfile,SSL_FILETYPE_PEM)))
      berr_exit("Can't read key file");

    return ctx;
  }



void destroy_ctx(SSL_CTX * ctx) {
    SSL_CTX_free(ctx);
  }

