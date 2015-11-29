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

void SSL_ServerClose(SSL *ssl,int server) {
	SSL_shutdown(ssl);
	SSL_clear(ssl);
	}

int SSL_connectToServer(SSL **ssl, SSL_CTX *ctx, const char *addr, int cport) {

	struct sockaddr_in sa;
	int sock;
	if(cport == 0)
		error("connectToServer bad port number",__FILE__,__LINE__);

// printf("SSL_connectToServer [%s:%d]\n",addr,cport);

	// Resolve the name to ip address ...
	struct hostent *host;
	if(!(host = gethostbyname(addr))) {
		fprintf(stderr,"SSL_connectToServer(%s) gethostbyname : %s\n",addr,hstrerror(h_errno));
		return(-1);
		}



	memset(&sa,'\0',sizeof(sa));
	if ((sock=socket(PF_INET,SOCK_STREAM,0)) < 0) {
		syslog(LOG_INFO,"socket %s:%d [%s]",__FILE__,__LINE__,strerror(errno));
		return(-1);
		}
	sa.sin_family = PF_INET;
	sa.sin_port = htons(cport);
	memcpy(&sa.sin_addr.s_addr,*host->h_addr_list,sizeof(sa.sin_addr.s_addr));

	if (connect(sock,(struct sockaddr *)&sa,sizeof(sa)) < 0) {
		syslog(LOG_INFO,"connect %s:%d [%s]",__FILE__,__LINE__,strerror(errno));
		return(-1);
		}

	BIO *sbio;
        sbio=BIO_new_socket(sock,BIO_NOCLOSE);
	SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
        *ssl=SSL_new(ctx);
        SSL_set_bio(*ssl,sbio,sbio);
        if(SSL_connect(*ssl)<=0)
          berr_exit("SSL connect error");
    	return(sock);
	}



// Writing to the SSL tunnel
int SSL_writeRead(int readSock, int writeSock, SSL *ssl) {
	char message[2048];
	int size=read(readSock,message,sizeof(message));
	if(size > 0) {
printf("From Socket\n[%*.*s]\n",size,size,message);
		int written;
		if((written=SSL_write(ssl, message, size)) != size) {
			char buffer[1024];
			snprintf(buffer,sizeof(buffer),"Short Write or Failure size=%d result=%d",size,written);
			error(buffer,__FILE__,__LINE__);
			}
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
int SSL_readWrite(int readSock, int writeSock, SSL *ssl) {
	char message[2048];
	int size=SSL_read(ssl,message,sizeof(message));
	if(size > 0) {
 printf("From SSL\n[%*.*s]\n",size,size,message);
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



int runServer(int sock, int server, SSL *ssl) {
	int retVal, fdMax;
	struct timeval tv;
	fd_set readSet;

	FD_ZERO(&readSet);
	FD_SET(sock,&readSet);		// non-ssl inbound connection
	FD_SET(server,&readSet);	// ssl outbound connection
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	fdMax = sock;
	if(server > sock)
		fdMax = server;

	int sslBytesPending = 0;
	while((retVal = select(fdMax+1,&readSet,NULL,NULL,&tv)) != -1) {
		if(sslBytesPending || FD_ISSET(server,&readSet)) {
			// Read from the SSL Tunnel, write to socket
			SSL_readWrite(server,sock,ssl);	// EOF cause process death and socket closure
			sslBytesPending = SSL_pending(ssl);	// Bytes in the SSL buffer (wouldn't see on socket)
			}

		if(FD_ISSET(sock,&readSet))
			// Read from socket, write to SSL tunnel
			SSL_writeRead(sock, server,ssl);	// EOF cause process death and socket closure

		FD_ZERO(&readSet);
		FD_SET(sock,&readSet);
		FD_SET(server,&readSet);
		if(sslBytesPending)
			tv.tv_sec = 0;	// no delay when there are bytes in the SSL buffer
		else
			tv.tv_sec = 1;
		tv.tv_usec = 0;
		}

	// Shouldn't get here are the readWrite and writeRead functions close and exit

	error("select error",__FILE__,__LINE__);	// termination
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
	SSL *ssl;

	FD_ZERO(&readSet);
	FD_SET(listener,&readSet);
	tv.tv_sec = 300;
	tv.tv_usec = 0;

	// while((retVal=select(listener+1,&readSet,NULL,NULL,&tv)) != -1){
	// Just allow one connection and it better happen within 5 seconds!
	retVal=select(listener+1,&readSet,NULL,NULL,&tv);
	if(FD_ISSET(listener,&readSet)) {
		struct sockaddr sa;
		socklen_t saSize = sizeof(sa);
		int sock;
		int server;

		// Connect to remote end first
		if((server=SSL_connectToServer(&ssl, ctx, remoteAddr, remotePort)) != -1) { // Connected

			// Good, now accept the incomming connection
			if((sock=accept(listener,&sa,&saSize)) < 0)
				error("accept",__FILE__,__LINE__);

			// All connections are good, start the tunnel
			runServer(sock,server,ssl);
			close(sock);
			SSL_ServerClose(ssl,server);
			close(server);
			}
		}

	if(retVal == -1)
		error("select",__FILE__,__LINE__);

	return(0);
	}

void usage(char *s) {

	if(s)
		fprintf(stderr,"\nERROR: %s\n\n",s);

	fprintf(stderr,"Connects to a remote SSL server if a connection is made on localListenPort\nusage:\n");
	fprintf(stderr,"\tsslConnect -c certFile -p password -l localListenPort -i serverAddr -r serverPort\n\n");
	fprintf(stderr,"\tNote: Password is simply for the inital connection\n\n");

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


	openlog("sslConnect", LOG_CONS|LOG_ODELAY, LOG_LOCAL6);

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

	SSL_CTX *ctx = initialize_ctx(certFile,password);


	// Start the listener that will cause the passthrough connection
	listenSocket=startListener(port);
	if(listenSocket > 0) {

		syslog(LOG_INFO,"init -> %s -c %s -l %d -i %s -r %d",argv[0],certFile,port,remoteAddr,remotePort);

		runAcceptor(listenSocket,ctx,remoteAddr,remotePort);
		close(listenSocket);
		exit(0);
		}
	else
		exit(-1);
	}


