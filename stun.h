#ifndef STUN_H
#define STUN_H

// 
// rfc 3489
// rfc 5389
// rfc 5780
//
#include <stdint.h>

namespace Stun
{

    struct MsgHeader
    {
        uint16_t type;
        uint16_t length;
        uint32_t magic;
        union {
            uint8_t tb[12];
            uint32_t tid[3];
        };
        uint8_t data[];
    } __attribute__((packed));

    struct MsgAttribute
    {
        uint16_t type;
        uint16_t length;
        uint8_t value[];
    } __attribute__((packed));

    enum MsgClassType
    {
        STUN_REQUEST               = 0x0000,
        STUN_INDICATION            = 0x0001,
        STUN_RESPONSE              = 0x0002,
        STUN_ERROR_RESP            = 0x0003
    };

    enum MsgMethodType
    {
        STUN_BINDING               = 0x0001,
        STUN_SHARED_SECRET         = 0x0002,
    };

    enum MsgAttributeType
    {
        STUN_MAPPED_ADDRESS        = 0x0001,
        STUN_RESPONSE_ADDRESS      = 0x0002,
        STUN_CHANGE_REQUEST        = 0x0003,
        STUN_SOURCE_ADDRESS        = 0x0004,
        STUN_CHANGED_ADDRESS       = 0x0005,
        STUN_USERNAME              = 0x0006,
        STUN_PASSWORD              = 0x0007,
        STUN_MESSAGE_INTEGRITY     = 0x0008,
        STUN_ERROR_CODE            = 0x0009,
        STUN_UNKNOWN_ATTRIBUTES    = 0x000a,
        STUN_REFLECTED_FROM        = 0x000b,
        STUN_REALM                 = 0x0014,
        STUN_NONCE                 = 0x0015,
        STUN_XOR_MAPPED_ADDRESS    = 0x0020,
        // STUN_PADDING               = 0x0026,
        // STUN_RESPONSE_PORT         = 0x0027,
        // STUN_XOR_MAPPED_ADDRESS    = 0x0020, // rfc 3489
        STUN_SOFTWARE              = 0x8022,
        STUN_ALTERNATE_SERVER      = 0x8023,
        STUN_FINGERPRINT           = 0x8028,
        // STUN_RESPONSE_ORIGIN       = 0x802b,
        // STUN_OTHER_ADDRESS         = 0x802c
    };

    static const uint32_t MagicCookie = 0x2112A442;
}

#endif
