file:/usr/include/netinet/in.h        (Sun Jun 6 05:39:45 2010 )        HOME

   1: /* Copyright (C) 1991-2001, 2003, 2004, 2006, 2007
   2:    Free Software Foundation, Inc.
   3:    This file is part of the GNU C Library.
   4: 
   5:    The GNU C Library is free software; you can redistribute it and/or
   6:    modify it under the terms of the GNU Lesser General Public
   7:    License as published by the Free Software Foundation; either
   8:    version 2.1 of the License, or (at your option) any later version.
   9: 
  10:    The GNU C Library is distributed in the hope that it will be useful,
  11:    but WITHOUT ANY WARRANTY; without even the implied warranty of
  12:    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  13:    Lesser General Public License for more details.
  14: 
  15:    You should have received a copy of the GNU Lesser General Public
  16:    License along with the GNU C Library; if not, write to the Free
  17:    Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
  18:    02111-1307 USA.  */
  19: 
  20: #ifndef _NETINET_IN_H
  21: #define _NETINET_IN_H   1
  22: 
  23: #include <features.h>
  24: #include <stdint.h>
  25: #include <sys/socket.h>
  26: #include <bits/types.h>
  27: 
  28: 
  29: __BEGIN_DECLS
  30: 
  31: /* Standard well-defined IP protocols.  */
  32: enum
  33:   {
  34:     IPPROTO_IP = 0,        /* Dummy protocol for TCP.  */
  35: #define IPPROTO_IP              IPPROTO_IP
  36:     IPPROTO_HOPOPTS = 0,   /* IPv6 Hop-by-Hop options.  */
  37: #define IPPROTO_HOPOPTS         IPPROTO_HOPOPTS
  38:     IPPROTO_ICMP = 1,      /* Internet Control Message Protocol.  */
  39: #define IPPROTO_ICMP            IPPROTO_ICMP
  40:     IPPROTO_IGMP = 2,      /* Internet Group Management Protocol. */
  41: #define IPPROTO_IGMP            IPPROTO_IGMP
  42:     IPPROTO_IPIP = 4,      /* IPIP tunnels (older KA9Q tunnels use 94).  */
  43: #define IPPROTO_IPIP            IPPROTO_IPIP
  44:     IPPROTO_TCP = 6,       /* Transmission Control Protocol.  */
  45: #define IPPROTO_TCP             IPPROTO_TCP
  46:     IPPROTO_EGP = 8,       /* Exterior Gateway Protocol.  */
  47: #define IPPROTO_EGP             IPPROTO_EGP
  48:     IPPROTO_PUP = 12,      /* PUP protocol.  */
  49: #define IPPROTO_PUP             IPPROTO_PUP
  50:     IPPROTO_UDP = 17,      /* User Datagram Protocol.  */
  51: #define IPPROTO_UDP             IPPROTO_UDP
  52:     IPPROTO_IDP = 22,      /* XNS IDP protocol.  */
  53: #define IPPROTO_IDP             IPPROTO_IDP
  54:     IPPROTO_TP = 29,       /* SO Transport Protocol Class 4.  */
  55: #define IPPROTO_TP              IPPROTO_TP
  56:     IPPROTO_IPV6 = 41,     /* IPv6 header.  */
  57: #define IPPROTO_IPV6            IPPROTO_IPV6
  58:     IPPROTO_ROUTING = 43,  /* IPv6 routing header.  */
  59: #define IPPROTO_ROUTING         IPPROTO_ROUTING
  60:     IPPROTO_FRAGMENT = 44, /* IPv6 fragmentation header.  */
  61: #define IPPROTO_FRAGMENT        IPPROTO_FRAGMENT
  62:     IPPROTO_RSVP = 46,     /* Reservation Protocol.  */
  63: #define IPPROTO_RSVP            IPPROTO_RSVP
  64:     IPPROTO_GRE = 47,      /* General Routing Encapsulation.  */
  65: #define IPPROTO_GRE             IPPROTO_GRE
  66:     IPPROTO_ESP = 50,      /* encapsulating security payload.  */
  67: #define IPPROTO_ESP             IPPROTO_ESP
  68:     IPPROTO_AH = 51,       /* authentication header.  */
  69: #define IPPROTO_AH              IPPROTO_AH
  70:     IPPROTO_ICMPV6 = 58,   /* ICMPv6.  */
  71: #define IPPROTO_ICMPV6          IPPROTO_ICMPV6
  72:     IPPROTO_NONE = 59,     /* IPv6 no next header.  */
  73: #define IPPROTO_NONE            IPPROTO_NONE
  74:     IPPROTO_DSTOPTS = 60,  /* IPv6 destination options.  */
  75: #define IPPROTO_DSTOPTS         IPPROTO_DSTOPTS
  76:     IPPROTO_MTP = 92,      /* Multicast Transport Protocol.  */
  77: #define IPPROTO_MTP             IPPROTO_MTP
  78:     IPPROTO_ENCAP = 98,    /* Encapsulation Header.  */
  79: #define IPPROTO_ENCAP           IPPROTO_ENCAP
  80:     IPPROTO_PIM = 103,     /* Protocol Independent Multicast.  */
  81: #define IPPROTO_PIM             IPPROTO_PIM
  82:     IPPROTO_COMP = 108,    /* Compression Header Protocol.  */
  83: #define IPPROTO_COMP            IPPROTO_COMP
  84:     IPPROTO_SCTP = 132,    /* Stream Control Transmission Protocol.  */
  85: #define IPPROTO_SCTP            IPPROTO_SCTP
  86:     IPPROTO_RAW = 255,     /* Raw IP packets.  */
  87: #define IPPROTO_RAW             IPPROTO_RAW
  88:     IPPROTO_MAX
  89:   };
  90: 
  91: 
  92: /* Type to represent a port.  */
  93: typedef uint16_t in_port_t;
  94: 
  95: /* Standard well-known ports.  */
  96: enum
  97:   {
  98:     IPPORT_ECHO = 7,            /* Echo service.  */
  99:     IPPORT_DISCARD = 9,         /* Discard transmissions service.  */
 100:     IPPORT_SYSTAT = 11,         /* System status service.  */
 101:     IPPORT_DAYTIME = 13,        /* Time of day service.  */
 102:     IPPORT_NETSTAT = 15,        /* Network status service.  */
 103:     IPPORT_FTP = 21,            /* File Transfer Protocol.  */
 104:     IPPORT_TELNET = 23,         /* Telnet protocol.  */
 105:     IPPORT_SMTP = 25,           /* Simple Mail Transfer Protocol.  */
 106:     IPPORT_TIMESERVER = 37,     /* Timeserver service.  */
 107:     IPPORT_NAMESERVER = 42,     /* Domain Name Service.  */
 108:     IPPORT_WHOIS = 43,          /* Internet Whois service.  */
 109:     IPPORT_MTP = 57,
 110: 
 111:     IPPORT_TFTP = 69,           /* Trivial File Transfer Protocol.  */
 112:     IPPORT_RJE = 77,
 113:     IPPORT_FINGER = 79,         /* Finger service.  */
 114:     IPPORT_TTYLINK = 87,
 115:     IPPORT_SUPDUP = 95,         /* SUPDUP protocol.  */
 116: 
 117: 
 118:     IPPORT_EXECSERVER = 512,    /* execd service.  */
 119:     IPPORT_LOGINSERVER = 513,   /* rlogind service.  */
 120:     IPPORT_CMDSERVER = 514,
 121:     IPPORT_EFSSERVER = 520,
 122: 
 123:     /* UDP ports.  */
 124:     IPPORT_BIFFUDP = 512,
 125:     IPPORT_WHOSERVER = 513,
 126:     IPPORT_ROUTESERVER = 520,
 127: 
 128:     /* Ports less than this value are reserved for privileged processes.  */
 129:     IPPORT_RESERVED = 1024,
 130: 
 131:     /* Ports greater this value are reserved for (non-privileged) servers.  */
 132:     IPPORT_USERRESERVED = 5000
 133:   };
 134: 
 135: 
 136: /* Internet address.  */
 137: typedef uint32_t in_addr_t;
 138: struct in_addr
 139:   {
 140:     in_addr_t s_addr;
 141:   };
 142: 
 143: 
 144: /* Definitions of the bits in an Internet address integer.
 145: 
 146:    On subnets, host and network parts are found according to
 147:    the subnet mask, not these masks.  */
 148: 
 149: #define IN_CLASSA(a)            ((((in_addr_t)(a)) & 0x80000000) == 0)
 150: #define IN_CLASSA_NET           0xff000000
 151: #define IN_CLASSA_NSHIFT        24
 152: #define IN_CLASSA_HOST          (0xffffffff & ~IN_CLASSA_NET)
 153: #define IN_CLASSA_MAX           128
 154: 
 155: #define IN_CLASSB(a)            ((((in_addr_t)(a)) & 0xc0000000) == 0x80000000)
 156: #define IN_CLASSB_NET           0xffff0000
 157: #define IN_CLASSB_NSHIFT        16
 158: #define IN_CLASSB_HOST          (0xffffffff & ~IN_CLASSB_NET)
 159: #define IN_CLASSB_MAX           65536
 160: 
 161: #define IN_CLASSC(a)            ((((in_addr_t)(a)) & 0xe0000000) == 0xc0000000)
 162: #define IN_CLASSC_NET           0xffffff00
 163: #define IN_CLASSC_NSHIFT        8
 164: #define IN_CLASSC_HOST          (0xffffffff & ~IN_CLASSC_NET)
 165: 
 166: #define IN_CLASSD(a)            ((((in_addr_t)(a)) & 0xf0000000) == 0xe0000000)
 167: #define IN_MULTICAST(a)         IN_CLASSD(a)
 168: 
 169: #define IN_EXPERIMENTAL(a)      ((((in_addr_t)(a)) & 0xe0000000) == 0xe0000000)
 170: #define IN_BADCLASS(a)          ((((in_addr_t)(a)) & 0xf0000000) == 0xf0000000)
 171: 
 172: /* Address to accept any incoming messages.  */
 173: #define INADDR_ANY              ((in_addr_t) 0x00000000)
 174: /* Address to send to all hosts.  */
 175: #define INADDR_BROADCAST        ((in_addr_t) 0xffffffff)
 176: /* Address indicating an error return.  */
 177: #define INADDR_NONE             ((in_addr_t) 0xffffffff)
 178: 
 179: /* Network number for local host loopback.  */
 180: #define IN_LOOPBACKNET          127
 181: /* Address to loopback in software to local host.  */
 182: #ifndef INADDR_LOOPBACK
 183: # define INADDR_LOOPBACK        ((in_addr_t) 0x7f000001) /* Inet 127.0.0.1.  */
 184: #endif
 185: 
 186: /* Defines for Multicast INADDR.  */
 187: #define INADDR_UNSPEC_GROUP     ((in_addr_t) 0xe0000000) /* 224.0.0.0 */
 188: #define INADDR_ALLHOSTS_GROUP   ((in_addr_t) 0xe0000001) /* 224.0.0.1 */
 189: #define INADDR_ALLRTRS_GROUP    ((in_addr_t) 0xe0000002) /* 224.0.0.2 */
 190: #define INADDR_MAX_LOCAL_GROUP  ((in_addr_t) 0xe00000ff) /* 224.0.0.255 */
 191: 
 192: 
 193: /* IPv6 address */
 194: struct in6_addr
 195:   {
 196:     union
 197:       {
 198:         uint8_t u6_addr8[16];
 199:         uint16_t u6_addr16[8];
 200:         uint32_t u6_addr32[4];
 201:       } in6_u;
 202: #define s6_addr                 in6_u.u6_addr8
 203: #define s6_addr16               in6_u.u6_addr16
 204: #define s6_addr32               in6_u.u6_addr32
 205:   };
 206: 
 207: extern const struct in6_addr in6addr_any;        /* :: */
 208: extern const struct in6_addr in6addr_loopback;   /* ::1 */
 209: #define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
 210: #define IN6ADDR_LOOPBACK_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }
 211: 
 212: #define INET_ADDRSTRLEN 16
 213: #define INET6_ADDRSTRLEN 46
 214: 
 215: 
 216: /* Structure describing an Internet socket address.  */
 217: struct sockaddr_in
 218:   {
 219:     __SOCKADDR_COMMON (sin_);
 220:     in_port_t sin_port;                 /* Port number.  */
 221:     struct in_addr sin_addr;            /* Internet address.  */
 222: 
 223:     /* Pad to size of `struct sockaddr'.  */
 224:     unsigned char sin_zero[sizeof (struct sockaddr) -
 225:                            __SOCKADDR_COMMON_SIZE -
 226:                            sizeof (in_port_t) -
 227:                            sizeof (struct in_addr)];
 228:   };
 229: 
 230: /* Ditto, for IPv6.  */
 231: struct sockaddr_in6
 232:   {
 233:     __SOCKADDR_COMMON (sin6_);
 234:     in_port_t sin6_port;        /* Transport layer port # */
 235:     uint32_t sin6_flowinfo;     /* IPv6 flow information */
 236:     struct in6_addr sin6_addr;  /* IPv6 address */
 237:     uint32_t sin6_scope_id;     /* IPv6 scope-id */
 238:   };
 239: 
 240: 
 241: /* IPv4 multicast request.  */
 242: struct ip_mreq
 243:   {
 244:     /* IP multicast address of group.  */
 245:     struct in_addr imr_multiaddr;
 246: 
 247:     /* Local IP address of interface.  */
 248:     struct in_addr imr_interface;
 249:   };
 250: 
 251: struct ip_mreq_source
 252:   {
 253:     /* IP multicast address of group.  */
 254:     struct in_addr imr_multiaddr;
 255: 
 256:     /* IP address of source.  */
 257:     struct in_addr imr_interface;
 258: 
 259:     /* IP address of interface.  */
 260:     struct in_addr imr_sourceaddr;
 261:   };
 262: 
 263: /* Likewise, for IPv6.  */
 264: struct ipv6_mreq
 265:   {
 266:     /* IPv6 multicast address of group */
 267:     struct in6_addr ipv6mr_multiaddr;
 268: 
 269:     /* local interface */
 270:     unsigned int ipv6mr_interface;
 271:   };
 272: 
 273: 
 274: /* Multicast group request.  */
 275: struct group_req
 276:   {
 277:     /* Interface index.  */
 278:     uint32_t gr_interface;
 279: 
 280:     /* Group address.  */
 281:     struct sockaddr_storage gr_group;
 282:   };
 283: 
 284: struct group_source_req
 285:   {
 286:     /* Interface index.  */
 287:     uint32_t gsr_interface;
 288: 
 289:     /* Group address.  */
 290:     struct sockaddr_storage gsr_group;
 291: 
 292:     /* Source address.  */
 293:     struct sockaddr_storage gsr_source;
 294:   };
 295: 
 296: 
 297: /* Full-state filter operations.  */
 298: struct ip_msfilter
 299:   {
 300:     /* IP multicast address of group.  */
 301:     struct in_addr imsf_multiaddr;
 302: 
 303:     /* Local IP address of interface.  */
 304:     struct in_addr imsf_interface;
 305: 
 306:     /* Filter mode.  */
 307:     uint32_t imsf_fmode;
 308: 
 309:     /* Number of source addresses.  */
 310:     uint32_t imsf_numsrc;
 311:     /* Source addresses.  */
 312:     struct in_addr imsf_slist[1];
 313:   };
 314: 
 315: #define IP_MSFILTER_SIZE(numsrc) (sizeof (struct ip_msfilter) \
 316:                                   - sizeof (struct in_addr)                   \
 317:                                   + (numsrc) * sizeof (struct in_addr))
 318: 
 319: struct group_filter
 320:   {
 321:     /* Interface index.  */
 322:     uint32_t gf_interface;
 323: 
 324:     /* Group address.  */
 325:     struct sockaddr_storage gf_group;
 326: 
 327:     /* Filter mode.  */
 328:     uint32_t gf_fmode;
 329: 
 330:     /* Number of source addresses.  */
 331:     uint32_t gf_numsrc;
 332:     /* Source addresses.  */
 333:     struct sockaddr_storage gf_slist[1];
 334: };
 335: 
 336: #define GROUP_FILTER_SIZE(numsrc) (sizeof (struct group_filter) \
 337:                                    - sizeof (struct sockaddr_storage)         \
 338:                                    + ((numsrc)                                \
 339:                                       * sizeof (struct sockaddr_storage)))
 340: 
 341: 
 342: /* Get system-specific definitions.  */
 343: #include <bits/in.h>
 344: 
 345: /* Functions to convert between host and network byte order.
 346: 
 347:    Please note that these functions normally take `unsigned long int' or
 348:    `unsigned short int' values as arguments and also return them.  But
 349:    this was a short-sighted decision since on different systems the types
 350:    may have different representations but the values are always the same.  */
 351: 
 352: extern uint32_t ntohl (uint32_t __netlong) __THROW __attribute__ ((__const__));
 353: extern uint16_t ntohs (uint16_t __netshort)
 354:      __THROW __attribute__ ((__const__));
 355: extern uint32_t htonl (uint32_t __hostlong)
 356:      __THROW __attribute__ ((__const__));
 357: extern uint16_t htons (uint16_t __hostshort)
 358:      __THROW __attribute__ ((__const__));
 359: 
 360: #include <endian.h>
 361: 
 362: /* Get machine dependent optimized versions of byte swapping functions.  */
 363: #include <bits/byteswap.h>
 364: 
 365: #ifdef __OPTIMIZE__
 366: /* We can optimize calls to the conversion functions.  Either nothing has
 367:    to be done or we are using directly the byte-swapping functions which
 368:    often can be inlined.  */
 369: # if __BYTE_ORDER == __BIG_ENDIAN
 370: /* The host byte order is the same as network byte order,
 371:    so these functions are all just identity.  */
 372: # define ntohl(x)       (x)
 373: # define ntohs(x)       (x)
 374: # define htonl(x)       (x)
 375: # define htons(x)       (x)
 376: # else
 377: #  if __BYTE_ORDER == __LITTLE_ENDIAN
 378: #   define ntohl(x)     __bswap_32 (x)
 379: #   define ntohs(x)     __bswap_16 (x)
 380: #   define htonl(x)     __bswap_32 (x)
 381: #   define htons(x)     __bswap_16 (x)
 382: #  endif
 383: # endif
 384: #endif
 385: 
 386: #define IN6_IS_ADDR_UNSPECIFIED(a) \
 387:         (((__const uint32_t *) (a))[0] == 0                                   \
 388:          && ((__const uint32_t *) (a))[1] == 0                                \
 389:          && ((__const uint32_t *) (a))[2] == 0                                \
 390:          && ((__const uint32_t *) (a))[3] == 0)
 391: 
 392: #define IN6_IS_ADDR_LOOPBACK(a) \
 393:         (((__const uint32_t *) (a))[0] == 0                                   \
 394:          && ((__const uint32_t *) (a))[1] == 0                                \
 395:          && ((__const uint32_t *) (a))[2] == 0                                \
 396:          && ((__const uint32_t *) (a))[3] == htonl (1))
 397: 
 398: #define IN6_IS_ADDR_MULTICAST(a) (((__const uint8_t *) (a))[0] == 0xff)
 399: 
 400: #define IN6_IS_ADDR_LINKLOCAL(a) \
 401:         ((((__const uint32_t *) (a))[0] & htonl (0xffc00000))                 \
 402:          == htonl (0xfe800000))
 403: 
 404: #define IN6_IS_ADDR_SITELOCAL(a) \
 405:         ((((__const uint32_t *) (a))[0] & htonl (0xffc00000))                 \
 406:          == htonl (0xfec00000))
 407: 
 408: #define IN6_IS_ADDR_V4MAPPED(a) \
 409:         ((((__const uint32_t *) (a))[0] == 0)                                 \
 410:          && (((__const uint32_t *) (a))[1] == 0)                              \
 411:          && (((__const uint32_t *) (a))[2] == htonl (0xffff)))
 412: 
 413: #define IN6_IS_ADDR_V4COMPAT(a) \
 414:         ((((__const uint32_t *) (a))[0] == 0)                                 \
 415:          && (((__const uint32_t *) (a))[1] == 0)                              \
 416:          && (((__const uint32_t *) (a))[2] == 0)                              \
 417:          && (ntohl (((__const uint32_t *) (a))[3]) > 1))
 418: 
 419: #define IN6_ARE_ADDR_EQUAL(a,b) \
 420:         ((((__const uint32_t *) (a))[0] == ((__const uint32_t *) (b))[0])     \
 421:          && (((__const uint32_t *) (a))[1] == ((__const uint32_t *) (b))[1])  \
 422:          && (((__const uint32_t *) (a))[2] == ((__const uint32_t *) (b))[2])  \
 423:          && (((__const uint32_t *) (a))[3] == ((__const uint32_t *) (b))[3]))
 424: 
 425: /* Bind socket to a privileged IP port.  */
 426: extern int bindresvport (int __sockfd, struct sockaddr_in *__sock_in) __THROW;
 427: 
 428: /* The IPv6 version of this function.  */
 429: extern int bindresvport6 (int __sockfd, struct sockaddr_in6 *__sock_in)
 430:      __THROW;
 431: 
 432: 
 433: #define IN6_IS_ADDR_MC_NODELOCAL(a) \
 434:         (IN6_IS_ADDR_MULTICAST(a)                                             \
 435:          && ((((__const uint8_t *) (a))[1] & 0xf) == 0x1))
 436: 
 437: #define IN6_IS_ADDR_MC_LINKLOCAL(a) \
 438:         (IN6_IS_ADDR_MULTICAST(a)                                             \
 439:          && ((((__const uint8_t *) (a))[1] & 0xf) == 0x2))
 440: 
 441: #define IN6_IS_ADDR_MC_SITELOCAL(a) \
 442:         (IN6_IS_ADDR_MULTICAST(a)                                             \
 443:          && ((((__const uint8_t *) (a))[1] & 0xf) == 0x5))
 444: 
 445: #define IN6_IS_ADDR_MC_ORGLOCAL(a) \
 446:         (IN6_IS_ADDR_MULTICAST(a)                                             \
 447:          && ((((__const uint8_t *) (a))[1] & 0xf) == 0x8))
 448: 
 449: #define IN6_IS_ADDR_MC_GLOBAL(a) \
 450:         (IN6_IS_ADDR_MULTICAST(a)                                             \
 451:          && ((((__const uint8_t *) (a))[1] & 0xf) == 0xe))
 452: 
 453: /* IPv6 packet information.  */
 454: struct in6_pktinfo
 455:   {
 456:     struct in6_addr ipi6_addr;  /* src/dst IPv6 address */
 457:     unsigned int ipi6_ifindex;  /* send/recv interface index */
 458:   };
 459: 
 460: /* IPv6 MTU information.  */
 461: struct ip6_mtuinfo
 462:   {
 463:     struct sockaddr_in6 ip6m_addr; /* dst address including zone ID */
 464:     uint32_t ip6m_mtu;             /* path MTU in host byte order */
 465:   };
 466: 
 467: 
 468: #ifdef __USE_GNU
 469: /* Obsolete hop-by-hop and Destination Options Processing (RFC 2292).  */
 470: extern int inet6_option_space (int __nbytes)
 471:      __THROW __attribute_deprecated__;
 472: extern int inet6_option_init (void *__bp, struct cmsghdr **__cmsgp,
 473:                               int __type) __THROW __attribute_deprecated__;
 474: extern int inet6_option_append (struct cmsghdr *__cmsg,
 475:                                 __const uint8_t *__typep, int __multx,
 476:                                 int __plusy) __THROW __attribute_deprecated__;
 477: extern uint8_t *inet6_option_alloc (struct cmsghdr *__cmsg, int __datalen,
 478:                                     int __multx, int __plusy)
 479:      __THROW __attribute_deprecated__;
 480: extern int inet6_option_next (__const struct cmsghdr *__cmsg,
 481:                               uint8_t **__tptrp)
 482:      __THROW __attribute_deprecated__;
 483: extern int inet6_option_find (__const struct cmsghdr *__cmsg,
 484:                               uint8_t **__tptrp, int __type)
 485:      __THROW __attribute_deprecated__;
 486: 
 487: 
 488: /* Hop-by-Hop and Destination Options Processing (RFC 3542).  */
 489: extern int inet6_opt_init (void *__extbuf, socklen_t __extlen) __THROW;
 490: extern int inet6_opt_append (void *__extbuf, socklen_t __extlen, int __offset,
 491:                              uint8_t __type, socklen_t __len, uint8_t __align,
 492:                              void **__databufp) __THROW;
 493: extern int inet6_opt_finish (void *__extbuf, socklen_t __extlen, int __offset)
 494:      __THROW;
 495: extern int inet6_opt_set_val (void *__databuf, int __offset, void *__val,
 496:                               socklen_t __vallen) __THROW;
 497: extern int inet6_opt_next (void *__extbuf, socklen_t __extlen, int __offset,
 498:                            uint8_t *__typep, socklen_t *__lenp,
 499:                            void **__databufp) __THROW;
 500: extern int inet6_opt_find (void *__extbuf, socklen_t __extlen, int __offset,
 501:                            uint8_t __type, socklen_t *__lenp,
 502:                            void **__databufp) __THROW;
 503: extern int inet6_opt_get_val (void *__databuf, int __offset, void *__val,
 504:                               socklen_t __vallen) __THROW;
 505: 
 506: 
 507: /* Routing Header Option (RFC 3542).  */
 508: extern socklen_t inet6_rth_space (int __type, int __segments) __THROW;
 509: extern void *inet6_rth_init (void *__bp, socklen_t __bp_len, int __type,
 510:                              int __segments) __THROW;
 511: extern int inet6_rth_add (void *__bp, __const struct in6_addr *__addr) __THROW;
 512: extern int inet6_rth_reverse (__const void *__in, void *__out) __THROW;
 513: extern int inet6_rth_segments (__const void *__bp) __THROW;
 514: extern struct in6_addr *inet6_rth_getaddr (__const void *__bp, int __index)
 515:      __THROW;
 516: 
 517: 
 518: /* Multicast source filter support.  */
 519: 
 520: /* Get IPv4 source filter.  */
 521: extern int getipv4sourcefilter (int __s, struct in_addr __interface_addr,
 522:                                 struct in_addr __group, uint32_t *__fmode,
 523:                                 uint32_t *__numsrc, struct in_addr *__slist)
 524:      __THROW;
 525: 
 526: /* Set IPv4 source filter.  */
 527: extern int setipv4sourcefilter (int __s, struct in_addr __interface_addr,
 528:                                 struct in_addr __group, uint32_t __fmode,
 529:                                 uint32_t __numsrc,
 530:                                 __const struct in_addr *__slist)
 531:      __THROW;
 532: 
 533: 
 534: /* Get source filter.  */
 535: extern int getsourcefilter (int __s, uint32_t __interface_addr,
 536:                             __const struct sockaddr *__group,
 537:                             socklen_t __grouplen, uint32_t *__fmode,
 538:                             uint32_t *__numsrc,
 539:                             struct sockaddr_storage *__slist) __THROW;
 540: 
 541: /* Set source filter.  */
 542: extern int setsourcefilter (int __s, uint32_t __interface_addr,
 543:                             __const struct sockaddr *__group,
 544:                             socklen_t __grouplen, uint32_t __fmode,
 545:                             uint32_t __numsrc,
 546:                             __const struct sockaddr_storage *__slist) __THROW;
 547: #endif  /* use GNU */
 548: 
 549: __END_DECLS
 550: 
 551: #endif  /* netinet/in.h */

