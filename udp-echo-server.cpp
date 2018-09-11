#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <getopt.h>

#include "stun.h"

#define APP_NAME    "udp-echo-server"
#define APP_VERSION "0.1"

#ifndef NDEBUG
#define DLOG(fmt, ...) \
    fprintf(stdout, "%s(%d): " fmt "\n", \
            __func__, __LINE__, ##__VA_ARGS__);
#else
#define DLOG(fmt, ...)
#endif

static struct 
{
    const char *IP = "0.0.0.0";
    const char *Port = NULL;
    int rto = 500;
    int max_retry = 3;
} sOpts;

#ifndef NDEBUG
inline void
printHex(const char *data, size_t len)
{
    for (size_t i=0; i<len; i+=4)
    {
        DLOG("%08x", *((uint32_t *) (data + i)));
    }
}
#endif

int udpEchoServer()
{
    struct addrinfo hints, *res;

    bzero(&hints, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;
    
    if (getaddrinfo(sOpts.IP,
                    sOpts.Port,
                    &hints,
                    &res) < 0)
    {
        perror("getaddrinfo failed");
        return -1;
    }

    int sock = socket(res->ai_family,
                      res->ai_socktype,
                      0);

    if (sock < 0)
    {
        perror("socket failed");
        return -1;
    }

    int optval = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (bind(sock, res->ai_addr, res->ai_addrlen) < 0)
    {
        perror("bind failed");
        close(sock);
        return -1;
    }

    int rc;

    for(;;)
    {
        char tmp[1024];
        struct sockaddr_in client_addr;
        socklen_t client_len;

        rc = recvfrom(sock,
                      tmp,
                      1024,
                      0,
                      (struct sockaddr *) &client_addr,
                      &client_len);

        if (rc < 0)
        {
            perror("recvfrom failed");
            continue;
        }

        DLOG("recv: %s", tmp);

        rc = sendto(sock,
                    tmp,
                    rc,
                    0,
                    (struct sockaddr *) &client_addr,
                    client_len);

        if (rc < 0)
        {
            perror("sendto failed");
            continue;
        }
    }

    freeaddrinfo(res);
    return 0;
}

static void ShowHelp()
{
    printf(APP_NAME " " APP_VERSION "\n");
    printf("\n");
    printf("Usage: " APP_NAME " [Options]\n");
    printf("\n");
    printf("Options:\n");
    printf(" -h                       print this help\n");
    printf(" -i, --ip [str]           local ip\n");
    printf(" -p, --port [num]         local port\n");
}

int main(int argc, char *argv[])
{
    int opt;

    static const struct option long_options[] =
    {
        { "ip", required_argument, 0, 'i' },
        { "port", required_argument, 0, 'p' },
        { 0, 0, 0, 0 }
    };

    while((opt = getopt_long(argc,
                             argv,
                             "hi:p:",
                             long_options,
                             NULL)) != -1)
    { 
        switch(opt)
        {
            case 'h':
            {
                ShowHelp();
                return 0;
            }
            case 'i':
            {
                sOpts.IP = optarg;
                break;
            }
            case 'p':
            {
                sOpts.Port = optarg;
                break;
            }
            default:
            {
                ShowHelp();
                return 0;
            }
        }
    }

    return udpEchoServer();
}
