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

#define APP_NAME    "stun-test"
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

struct MyResult
{
    char ip[128];
    int port;
    char changed_ip[128];
    int changed_port;
};

using namespace Stun;

inline void
initMsg(MsgHeader *req)
{
    bzero(req, sizeof(MsgHeader));

    req->magic = htonl(MagicCookie);

    int fd = 0;

    do
    {
        fd = open("/dev/urandom", O_RDONLY);

        if (fd < 0)
        {
            break;
        }
        else
        {
            if (read(fd, req->tid, sizeof(req->tid)) < 0)
            {
                break;
            }
        }

        DLOG("%08x", *req->tid);

    } while (0);

    if (req->tid[0] == 0 &&
        req->tid[1] == 0 &&
        req->tid[2] == 0)
    {
        srandom(time(NULL));

        for (int i=0; i<3; ++i)
        {
            req->tid[i] = random();
        }
    }

    if (fd)
    {
        close(fd);
    }

    return;
}

inline int
msgType2Class(int msg)
{
	return \
	    ((msg & 0x0010) >> 4) | ((msg & 0x0100) >> 7);
}

inline int
msgType2Method(int msg)
{
	return \
	    (msg & 0x000f) | ((msg & 0x00e0) >> 1) |
	    ((msg & 0x3e00) >> 2);
}

inline int
formMsgType(int cls, int method)
{
    return  \
        ((cls & 1) << 4) | ((cls & 2) << 7) |
        (method & 0x000f) | ((method & 0x0070) << 1) |
        ((method & 0x0f800) << 2);
}

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

inline int
appendStrAttribute(
    MsgAttribute *attr,
    MsgAttributeType type,
    size_t maxlen,
    const char *s,
    size_t slen)
{
    size_t len = slen + ((~(slen - 1)) & 0x3);

    if (len > maxlen)
    {
        return -1;
    }

    DLOG("%ld:%ld", slen, len);

    attr->type = htons(type);
    attr->length = htons(len);

    memcpy(attr->value, s, slen);
    memset(attr->value + slen, 0, len - slen);

    return (len + sizeof(MsgAttribute));
}

inline int
appendChangeReqAttribute(MsgAttribute *attr, bool changeIP, bool changePort)
{
    uint8_t data[4];

    bzero(data, 4);
    data[3] = (changeIP << 2) | (changePort << 1);

    attr->type = htons(STUN_CHANGE_REQUEST);
    attr->length = htons(4);

    memcpy(attr->value, data, 4);
    DLOG("%02x %02x %02x %02x",
         data[0], data[1], data[2], data[3]); 
    return (4 + sizeof(MsgAttribute));
}

inline void
printClassType(uint16_t msgType)
{
    uint8_t cls = msgType2Class(msgType);

    switch (cls)
    {
        case STUN_REQUEST:
            DLOG("REQUEST");
            break;
        case STUN_INDICATION:
            DLOG("INDICATION");
            break;
        case STUN_RESPONSE:
            DLOG("RESPONSE");
            break;
        case STUN_ERROR_RESP:
            DLOG("ERR RESPONSE");
            break;
        default:
            DLOG("Unknown");
            break;
    }
}

inline void
printMethodType(uint16_t msgType)
{
    uint16_t method = msgType2Method(msgType);

    switch (method)
    {
        case STUN_BINDING:
            DLOG("BINDING");
            break;
        case STUN_SHARED_SECRET:
            DLOG("SHARED_SECRET");
            break;
        default:
            DLOG("Unknown");
            break;
    }
}

inline void
parseAddress(const char *data,
             char *tmp, size_t len,
             int &port)
{
    struct Address {
        uint8_t unused;
        uint8_t family;
        uint16_t port;
        uint8_t address[];
    } __attribute__ ((packed));

    Address *p = (Address*) data;

    switch (p->family)
    {
        case 0x01:
            DLOG("ipv4");
            inet_ntop(AF_INET, p->address, tmp, len);
            port = ntohs(p->port);
            DLOG("%s:%d", tmp, port);
            break;
        case 0x02:
            DLOG("ipv6");
            inet_ntop(AF_INET6, p->address, tmp, len);
            port = ntohs(p->port);
            DLOG("%s:%d", tmp, port);
            break;
        default:
            DLOG("unknow ip family");
            break;
    }
}

void processResponse(const char *data,
                     size_t datalen,
                     MyResult &res)
{
    const char *p = data;
    const char *end = data + datalen;

    char ip[128];
    int port;

    MsgHeader *resp = (MsgHeader *) data;

    uint16_t msgtype = ntohs(resp->type);
    // uint16_t msglen = ntohs(resp->length);

    if (datalen < sizeof(MsgHeader))
    {
        DLOG("too small");
        return;
    }

    datalen -= sizeof(MsgHeader);
    p += sizeof(MsgHeader);

    printClassType(msgtype);
    printMethodType(msgtype);

    // DLOG("msglen: %d", msglen);

    while (p < end)
    {
        MsgAttribute *attr = (MsgAttribute *) p;

        uint16_t type = ntohs(attr->type);
        uint16_t len = ntohs(attr->length);
        
        DLOG("type: %04x, len: %d", type, len);

        switch (type)
        {
            case STUN_MAPPED_ADDRESS:
                DLOG("MAPPED_ADDRESS");
                parseAddress((char*) attr->value, ip, 128, port);
                strcpy(res.ip, ip);
                res.port = port;
                break;
            case STUN_RESPONSE_ADDRESS:
                DLOG("RESPONSE_ADDRESS");
                parseAddress((char*) attr->value, ip, 128, port);
                break;
            case STUN_CHANGE_REQUEST:
                DLOG("CHANGE_REQUEST");
                parseAddress((char*) attr->value, ip, 128, port);
                break;
            case STUN_SOURCE_ADDRESS:
                DLOG("SOURCE_ADDRESS");
                parseAddress((char*) attr->value, ip, 128, port);
                break;
            case STUN_CHANGED_ADDRESS:
                DLOG("CHANGED_ADDRESS");
                parseAddress((char*) attr->value, ip, 128, port);
                strcpy(res.changed_ip, ip);
                res.changed_port = port;
                break;
            case STUN_USERNAME:
                DLOG("USERNAME");
                break;
            case STUN_PASSWORD:
                DLOG("PASSWORD");
                break;
            case STUN_MESSAGE_INTEGRITY:
                DLOG("MESSAGE_INTEGRITY");
                break;
            case STUN_ERROR_CODE:
                DLOG("ERROR_CODE");
                break;
            case STUN_UNKNOWN_ATTRIBUTES:
                DLOG("UNKNOWN_ATTRIBUTES");
                break;
            case STUN_REFLECTED_FROM:
                DLOG("REFLECTED_FROM");
                break;
            case STUN_REALM:
                DLOG("REALM");
                break;
            case STUN_NONCE:
                DLOG("NONCE");
                break;
            case STUN_XOR_MAPPED_ADDRESS:
                DLOG("XOR_MAPPED_ADDRESS");
                break;
            case STUN_SOFTWARE:
                DLOG("SOFTWARE");
                DLOG("%s", attr->value);
                break;
            case STUN_ALTERNATE_SERVER:
                DLOG("ALTERNATE_SERVER");
                break;
            case STUN_FINGERPRINT:
                DLOG("FINGERPRINT");
                break;
            default:
                DLOG("Unknown");
                break;
        }

        p += (len + sizeof(MsgAttribute));
    }
}

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

int 
doTest1(int sock,
        struct sockaddr *to,
        socklen_t tolen,
        MyResult &res)
{
    char data[1024];
    const char *tail;
    size_t remain = 0;

    MsgHeader *req;

    ssize_t rc = 0;

    req = (MsgHeader*) data;

    tail = (char*) req->data;
    remain = sizeof(data) - sizeof(MsgHeader);

    initMsg(req);

    rc = appendStrAttribute(
            (MsgAttribute*) tail,
            STUN_SOFTWARE,
            remain,
            APP_NAME " " APP_VERSION,
            strlen(APP_NAME " " APP_VERSION));

    if (rc < 0)
    {
        return -1;
    }

    tail += rc;
    remain -= rc;

    req->length = htons(tail - data - sizeof(MsgHeader));
    req->type = htons(formMsgType(STUN_REQUEST, STUN_BINDING));
    
    DLOG("size: %ld", tail - data - sizeof(MsgHeader));
    DLOG("type; 0x%08x", req->type);

#ifndef NDEBUG
    // printHex(data, tail - data);
#endif

    char resp[1024];

    rc = sendReceive(
            sock,
            to, tolen,
            data, tail - data,
            resp, 1024);
    
    if (rc <= 0)
    {
        DLOG("send failed");
        return -1;
    }

    processResponse(resp, rc, res);

    return 0;
}

int 
doTest2(int sock,
        struct sockaddr *to,
        socklen_t tolen,
        bool changeIp,
        bool changePort,
        MyResult &res)
{
    char data[1024];
    const char *tail;
    size_t remain = 0;

    MsgHeader *req;

    ssize_t rc = 0;

    req = (MsgHeader*) data;

    tail = (char*) req->data;
    remain = sizeof(data) - sizeof(MsgHeader);


    initMsg(req);

    rc = appendStrAttribute(
            (MsgAttribute*) tail,
            STUN_SOFTWARE,
            remain,
            APP_NAME " " APP_VERSION,
            strlen(APP_NAME " " APP_VERSION));

    if (rc < 0)
    {
        return -1;
    }

    tail += rc;
    remain -= rc;

    rc = appendChangeReqAttribute(
            (MsgAttribute*) tail,
            changeIp,
            changePort);

    tail += rc;
    remain -= rc;

    req->length = htons(tail - data - sizeof(MsgHeader));
    req->type = htons(formMsgType(STUN_REQUEST, STUN_BINDING));
    
    DLOG("size: %ld", tail - data - sizeof(MsgHeader));
    DLOG("type: 0x%08x", req->type);

#ifndef NDEBUG
    // printHex(data, tail - data);
#endif

    char resp[1024];

    rc = sendReceive(
            sock,
            to, tolen,
            data, tail - data,
            resp, 1024);
    
    if (rc <= 0)
    {
        DLOG("send failed");
        return -1;
    }

    processResponse(resp, rc, res);
    return 0;
}

int openSocket(int family, int socktype, int protocol, int port = 0)
{
    int sock = 0;
    struct sockaddr_in addr;

    DLOG("%d:%d", family, socktype);

    sock = socket(family, socktype, protocol);

    if (sock < 0)
    {
        perror("create socket failed");
        return -1;
    }

    int optval = 1;

    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    do
    {
        bzero(&addr, sizeof(addr));

        if (inet_pton(AF_INET, sOpts.IP, &addr) < 0)
        {
            perror("inet_pton failed");
            break;
        }
        
        addr.sin_port = htons(port);

        if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        {
            perror("bind");
            break;
        }

        return sock;

    } while (0);

    if (sock)
    {
        close(sock);
    }

    return -1;
}

int getNATType()
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

    MyResult res1, res2;
    int rc = -1;

    for (auto srv = srvInfos; srv; srv = srv->ai_next)
    {
        int sock = openSocket(srv->ai_family,
                              srv->ai_socktype,
                              0,
                              atoi(sOpts.Port));

        if (sock < 0)
        {
            DLOG("open socket failed");
            break;
        }

        do
        {
            // TEST1
            if (doTest1(sock,
                        srv->ai_addr,
                        srv->ai_addrlen,
                        res1) < 0)
            {
                DLOG("UDP blocked");
                break;
            }

            // TEST2
            if (doTest2(sock,
                        srv->ai_addr,
                        srv->ai_addrlen,
                        true,
                        true,
                        res2) == 0)
            {
                DLOG("full cone");
                rc = 0; //Full Cone
                break;
            }

            DLOG("%s:%d", res1.changed_ip, res1.changed_port);

            struct sockaddr_in alt_srv;

            alt_srv.sin_family = AF_INET;
            alt_srv.sin_addr.s_addr = inet_addr(res1.changed_ip);
            alt_srv.sin_port = htons(res1.changed_port);

            // TEST1 to alternate server ip
            if (doTest1(sock,
                        (struct sockaddr *) &alt_srv,
                        sizeof(struct sockaddr_in),
                        res2) < 0)
            {
                DLOG("doTest1 failed");
                break;
            }

            DLOG("%s:%d", res1.ip, res1.port);
            DLOG("%s:%d", res2.ip, res2.port);

            if ((strcmp(res1.ip, res2.ip) != 0) ||
                (res1.port != res2.port))
            {
                DLOG("Symmetric Nat");
                rc = 3;
                break;
            }

            // TEST3
            if (doTest2(sock,
                        srv->ai_addr,
                        srv->ai_addrlen,
                        false,
                        true,
                        res2) < 0)
            {
                DLOG("port restricted cone");
                rc = 2;
                break;
            }

            DLOG("restricted cone");
            rc = 1;

        } while (0);

        if (sock)
        {
            close(sock);

            if (rc < 0)
                continue;
            break;
        }
    }

    if (rc < 0)
    {
        printf("test failed\n");
    }
    else
    {
        const char *NAT[] = {
            "Full Cone",
            "Restricted Cone",
            "Port Restricted Cone",
            "Symmetric"
        };

        printf("==========================\n");
        printf("NAT Type: %s\n", NAT[rc]);
        printf("IP: %s\n", res1.ip);
        printf("Port: %d\n", res1.port);
    }

    freeaddrinfo(srvInfos);
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

    return getNATType();
}
