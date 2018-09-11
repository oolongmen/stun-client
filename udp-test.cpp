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

#define APP_NAME    "udp-test"
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
    const char *Port = "51024";
    const char *ServerIP = "stun.ekiga.net";
    const char *ServerPort = "3478";
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

ssize_t sendReceive(int sock,
                    struct sockaddr *to, socklen_t tolen,
                    const char *req, size_t reqlen,
                    char *resp, size_t resplen)
{
    ssize_t rc = 0;
    unsigned long timeout = sOpts.rto;

    for (auto retry =0; retry < sOpts.max_retry; ++retry)
    {
        struct timeval tv;
        // char resp[1024];
        fd_set rfds;

        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;

        rc = sendto(sock,
                    req,
                    reqlen,
                    0,
                    to,
                    tolen);

        if (rc < 0)
        {
            perror("sendto failed");
            continue;
        }

        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);

        rc = select(sock + 1,
                    &rfds,
                    NULL,
                    NULL,
                    &tv);

        if (rc < 0)
        {
            perror("select");
            continue;
        }
        else if (rc == 0)
        {
            DLOG("timeout: %ldms", timeout);
            timeout *= 2;
            continue;
        }
        
        bzero(resp, resplen);

        rc = recvfrom(sock,
                      resp,
                      resplen,
                      0,
                      NULL,
                      NULL);

        if (rc < 0)
        {
            perror("recvfrom failed");
            continue;
        }

        break;
    }

    DLOG("rc=%ld", rc);
    return rc;
}

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

int sendUDP(const char *msg)
{
    struct addrinfo hints;
    struct addrinfo *srvInfos;

    bzero(&hints, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    if (getaddrinfo(sOpts.ServerIP,
                    sOpts.ServerPort,
                    &hints,
                    &srvInfos) < 0)
    {
        perror("getaddrinfo failed");
        return -1;
    }

    int rc = -1;

    for (auto srv = srvInfos; srv; srv = srv->ai_next)
    {
        int sock = openBind(srv->ai_family,
                            srv->ai_socktype,
                            0);

        if (sock < 0)
        {
            DLOG("open socket failed");
            break;
        }

        do
        {
            char resp[1024];

            rc = sendReceive(
                    sock,
                    srv->ai_addr,
                    srv->ai_addrlen,
                    msg,
                    strlen(msg),
                    resp, 1024);
            
            if (rc <= 0)
            {
                DLOG("send failed");
                break;
            }

            printf("%s:%d\n", resp, strcmp(resp, msg));

        } while (0);

        if (sock)
        {
            close(sock);

            if (rc < 0)
                continue;
            break;
        }
    }

    freeaddrinfo(srvInfos);
    return 0;
}

static void ShowHelp()
{
    printf(APP_NAME " " APP_VERSION "\n");
    printf("\n");
    printf("Usage: " APP_NAME " [Options] [msg]\n");
    printf("\n");
    printf("Options:\n");
    printf(" -h                       print this help\n");
    printf(" -i, --ip [str]           local ip\n");
    printf(" -p, --port [num]         local port\n");
    printf(" -s, --sname [str]        stun server name or ip\n");
    printf(" -o, --sport [num]        stun server port\n");
}

int main(int argc, char *argv[])
{
    int opt;

    static const struct option long_options[] =
    {
        { "ip", required_argument, 0, 'i' },
        { "port", required_argument, 0, 'p' },
        { "sname", required_argument, 0, 's' },
        { "sport", required_argument, 0, 'o' },
        { 0, 0, 0, 0 }
    };

    while((opt = getopt_long(argc,
                             argv,
                             "hi:p:s:o:",
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
            case 's':
            {
                sOpts.ServerIP = optarg;
                break;
            }
            case 'o':
            {
                sOpts.ServerPort = optarg;
                break;
            }
            default:
            {
                ShowHelp();
                return 0;
            }
        }
    }

    if (optind == argc)
    {
        ShowHelp();
        return 0;
    }

    DLOG("%s", argv[optind]);
    return sendUDP(argv[optind]);
}
