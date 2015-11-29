#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <syslog.h>

#include <string.h>
#include <errno.h>

#include "sslTools.h"


void error(const char *s,const char *file, int lineNo) {
	syslog(LOG_ERR,"(%s:%d) %s: %s - EXIT",file,lineNo,s, strerror(errno));
	exit(-1);
	}


int connectToServer(const char *addr, int cport) {

    struct sockaddr_in sa;
    int sock;
    if(cport == 0)
	error("connectToServer bad port number",__FILE__,__LINE__);

    memset(&sa,'\0',sizeof(sa));
    if ((sock=socket(PF_INET,SOCK_STREAM,0)) < 0) {
	syslog(LOG_INFO,"socket %s:%d [%s]",__FILE__,__LINE__,strerror(errno));
	return(-1);
	}
    sa.sin_family = PF_INET;
    sa.sin_port = htons(cport);
    if (inet_pton(PF_INET,addr, &sa.sin_addr.s_addr)<0) {
	syslog(LOG_INFO,"inet_pton %s:%d [%s]",__FILE__,__LINE__,strerror(errno));
	return(-1);
	}
    if (connect(sock,(struct sockaddr *)&sa,sizeof(sa)) < 0) {
	syslog(LOG_INFO,"connect %s:%d [%s]",__FILE__,__LINE__,strerror(errno));
	return(-1);
	}

    return(sock);
    }



// Writing to the SSL tunnel
int BIO_writeRead(int readSock, int writeSock, BIO *bio, SSL *ssl) {
	char message[2048];
	int size=read(readSock,message,sizeof(message));
fprintf(stderr,"To SSL [%*.*s]\n",size,size,message);
	if(size > 0) {
		if(SSL_write(ssl, message, size) != size)
			error("Short Write or Failure",__FILE__,__LINE__);
		}
	else {
		if(size == 0) {
			// Normal case
			if(close(readSock)!=0)
				error("close error",__FILE__,__LINE__);
			// The reader side is an SSL connection
			int r=SSL_shutdown(ssl);
			if(!r){
				/* If we called SSL_shutdown() first then
				we always get return value of '0'. In
				this case, try again, but first send a
				TCP FIN to trigger the other side's
				close_notify*/
				close(writeSock);
				r=SSL_shutdown(ssl);
				}

			exit(0);	// exit ... this causes all open sockets to close on exit
			}
		else
			error("Socket Read Failure",__FILE__,__LINE__);
		}
	return(size);
	}

// Reading from SSL tunnel
int BIO_readWrite(int readSock, int writeSock, BIO *bio, SSL *ssl) {
	char message[2048];
	int size=SSL_read(ssl,message,sizeof(message));
fprintf(stderr,"From SSL [%*.*s]\n",size,size,message);
	if(size > 0) {
		if(write(writeSock, message, size) != size)
			error("Short Write or Failure",__FILE__,__LINE__);
		}
	else {
		if(size == 0) {
			// Normal case
			if(close(writeSock)!=0)
				error("close error",__FILE__,__LINE__);
			// The reader side is an SSL connection
			int r=SSL_shutdown(ssl);
			if(!r){
				/* If we called SSL_shutdown() first then
				we always get return value of '0'. In
				this case, try again, but first send a
				TCP FIN to trigger the other side's
				close_notify*/
				close(readSock);
				r=SSL_shutdown(ssl);
				}

			exit(0);	// exit ... this causes all open sockets to close on exit
			}
		else
			error("Socket Read Failure",__FILE__,__LINE__);
		}
	return(size);
	}



int runServer(int sock, SSL_CTX *ctx, char *ip, int port) {
	int server;

	SSL *ssl;
	BIO *sbio;
        sbio=BIO_new_socket(sock,BIO_NOCLOSE);
	SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
        ssl=SSL_new(ctx);
        SSL_set_bio(ssl,sbio,sbio);
	int r;

        if((r=SSL_accept(ssl)<=0))
          berr_exit("SSL accept error");

	BIO *io,*ssl_bio;

	io=BIO_new(BIO_f_buffer());
	ssl_bio=BIO_new(BIO_f_ssl());
	BIO_set_ssl(ssl_bio,ssl,BIO_CLOSE);
	BIO_push(io,ssl_bio);


	// Non-ssl connection starting

	if((server=connectToServer(ip, port)) != -1) { // Connect
		int retVal, fdMax;
		struct timeval tv;
		fd_set readSet;

fprintf(stderr,"Connected\n");

		FD_ZERO(&readSet);
		FD_SET(sock,&readSet);
		FD_SET(server,&readSet);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		fdMax = sock;
		if(server > sock)
			fdMax = server;

		int sslBytesPending = 0;
		while((retVal = select(fdMax+1,&readSet,NULL,NULL,&tv)) != -1) {
			if(sslBytesPending || FD_ISSET(sock,&readSet)) {
				// Read from the SSL Tunnel, write to socket
				BIO_readWrite(sock,server,io,ssl);	// EOF cause process death and socket closure
				sslBytesPending = SSL_pending(ssl);	// Bytes in the SSL buffer (wouldn't see on socket)
				}

			if(FD_ISSET(server,&readSet))
				// Read from socket, write to SSL tunnel
				BIO_writeRead(server, sock,io,ssl);	// EOF cause process death and socket closure

			FD_ZERO(&readSet);
			FD_SET(sock,&readSet);
			FD_SET(server,&readSet);
			if(sslBytesPending)
				tv.tv_sec = 0;	// no delay when there are bytes in the SSL buffer
			else
				tv.tv_sec = 1;
			tv.tv_usec = 0;
			}
		}


	// Only get here if connect failed out!
	sleep(1);	// let the messages deliver before the close (it can happen)
	close(sock);
	error("connect Failure",__FILE__,__LINE__);	// termination
	return(-1);
	}


int startListener(int port) {

	struct sockaddr_in sa;
	int val;
	int sock;

	if((sock=socket(PF_INET,SOCK_STREAM,0)) < 0)
		error("socket",__FILE__,__LINE__);

	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0)
		error("setsockopt",__FILE__,__LINE__);

	sa.sin_family = PF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(INADDR_ANY); 

	if(bind(sock,(struct sockaddr*)&sa,sizeof(sa)) < 0)
		error("bind",__FILE__,__LINE__);

	if(listen(sock,5) < 0)
		error("listen",__FILE__,__LINE__);
	return(sock);
	}

int runAcceptor(int listener, SSL_CTX *ctx, char *remoteAddr, int remotePort) {

	int retVal;
	struct timeval tv;
	fd_set readSet;

	FD_ZERO(&readSet);
	FD_SET(listener,&readSet);
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	while((retVal=select(listener+1,&readSet,NULL,NULL,&tv)) != -1){
		pid_t pid;
		int status;
		if(FD_ISSET(listener,&readSet)) {
			struct sockaddr sa;
			socklen_t saSize = sizeof(sa);
			int sock;

			if((sock=accept(listener,&sa,&saSize)) < 0)
				error("accept",__FILE__,__LINE__);

			if((pid=fork()) == 0)
				exit(runServer(sock,ctx,remoteAddr,remotePort));	// child code entry
			// Parent only
fprintf(stderr,"Child %d Started\n",pid);
			close(sock);
			}
		while((pid=waitpid(0,&status,WNOHANG))>0);	// clean up child process return codes

		FD_ZERO(&readSet);
		FD_SET(listener,&readSet);
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		}

	if(retVal == -1)
		error("select",__FILE__,__LINE__);

	return(0);
	}

void usage(char *s) {

	if(s)
		fprintf(stderr,"\nERROR: %s\n\n",s);

	fprintf(stderr,"usage:\n");
	fprintf(stderr,"\tsslTunnel -c certFile -p password -l listenPort -i remoteAddr -r remotePort\n\n");

	syslog(LOG_ERR,"usage error");

	exit(-1);
	}



int main(int argc, char *argv[]) {
	int listenSocket;
	char *certFile = NULL;
	int port = -1;
	int remotePort = -1;
	char *remoteAddr = NULL;
	char *password = NULL;


	openlog("sslTunnel", LOG_CONS|LOG_ODELAY, LOG_LOCAL6);

	int x;
	for(x=1;x<argc;x++) {
		if(argv[x][0] == '-') {
			switch(argv[x][1]) {
				case 'r':
					remotePort = atoi(argv[++x]);
					break;
				case 'p':
					password = argv[++x];
					break;
				case 'i':
					remoteAddr = argv[++x];
					break;
				case 'l':
					port = atoi(argv[++x]);
					break;
				case 'c':
					certFile = argv[++x];
					break;
				default:
					usage("unrecognized option flag");
				}
			}
		else
			usage("unrecognized parameter");
		}

	if(remotePort == -1)
		usage("missing remote port");
	if(remoteAddr == NULL)
		usage("missing remote address");
	if(port == -1)
		usage("missing listen port");
	if(certFile == NULL)
		usage("missing certificate file");
	if(password == NULL)
		usage("missing Password Key");

	if(access(certFile,R_OK) != 0)
		usage("Unable to access certificate file");

	syslog(LOG_INFO,"%s -c %s -l %d -i %s -r %d",argv[0],certFile,port,remoteAddr,remotePort);
	SSL_CTX *ctx = initialize_ctx(certFile,password);

	syslog(LOG_INFO,"sslTunnel - init complete\n");

	// Run the redirector code now ... running on the "well known" port
	listenSocket=startListener(port);
	exit(runAcceptor(listenSocket,ctx,remoteAddr,remotePort));
	}


