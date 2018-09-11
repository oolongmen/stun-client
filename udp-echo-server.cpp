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

int openBind(int family, int socktype, int protocol)
{
    int sock = -1;
    struct addrinfo hints, *res = NULL;
    int optval = 1;

    bzero(&hints, sizeof(hints));

    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_flags = 0;
    hints.ai_protocol = protocol;

    if (getaddrinfo(sOpts.IP,
                    sOpts.Port,
                    &hints,
                    &res) < 0)
    {
        perror("getaddrinfo failed");
        return -1;
    }

    do
    {
        sock = socket(res->ai_family,
                      res->ai_socktype,
                      res->ai_protocol);

        if (sock < 0)
        {
            perror("create socket failed");
            break;
        }

        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
                   &optval, sizeof(optval));

        if (bind(sock,
                 res->ai_addr,
                 res->ai_addrlen) < 0)
        {
            perror("bind");
            break;
        }

        freeaddrinfo(res);
        return sock;

    } while (0);

    if (sock >= 0)
        close(sock);

    if (res)
        freeaddrinfo(res);

    return -1;
}

int udpEchoServer()
{
    int sock = openBind(AF_UNSPEC, SOCK_DGRAM, 0);

    if (sock < 0)
    {
        perror("socket failed");
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
