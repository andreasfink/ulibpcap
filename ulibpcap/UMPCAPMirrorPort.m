//
//  UMPCAPMirrorPort.m
//  ulibpcap
//
//  Created by Andreas Fink on 09.05.22.
//  Copyright © 2022 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import "UMPCAPMirrorPort.h"
#import "UMPCAPPseudoConnection.h"

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#ifdef __LINUX__
#include <netinet/ether.h>
#include <linux/if_packet.h>
#endif

@implementation UMPCAPMirrorPort

- (UMPCAPMirrorPort *)initWithLinkNumber:(int)linkNumber
{
    self = [super init];
    if(self)
    {
        _linkNumber = linkNumber;
        uint8_t srcAddr[] = { 0x70,0xB3,0xD5,0x23,0xB0,0x00 };
        uint8_t x = linkNumber % 254 + 1;
        uint8_t dstAddr[] = { 0x70,0xB3,0xD5,0x23,0xB0,x };
        _localMacAddress = [NSData dataWithBytes:srcAddr length:sizeof(srcAddr)];
        _remoteMacAddress = [NSData dataWithBytes:dstAddr length:sizeof(dstAddr)];
    }
    return self;
}

+ (NSData *)macAddressFromString:(NSString *)in
{
    NSArray *a = [in componentsSeparatedByString:@":"];
    if(a.count != 6)
    {
        return NULL;
    }
    NSMutableData *addr = [[NSMutableData alloc]init];
    for(int i=0;i<6;i++)
    {
        NSString *b = a[i];
        NSData *d = [b unhexedData];
        [addr appendData:d];
    }
    return addr;
}

- (void)setConfig:(NSDictionary *)dict
{
    NSString *localMacAddressString     = dict[@"local-mac-address"];
    if(localMacAddressString.length > 0)
    {
        NSData *d = [UMPCAPMirrorPort macAddressFromString:localMacAddressString];
        if(d)
        {
            _localMacAddress = d;
        }
    }
    NSString *remoteMacAddressString    = dict[@"remote-mac-address"];
    if(remoteMacAddressString.length > 0)
    {
        NSData *d = [UMPCAPMirrorPort macAddressFromString:remoteMacAddressString];
        if(d)
        {
            _remoteMacAddress = d;
        }
    }
}


- (UMPCAPMirrorPort_error)openDevice
{
    return - [self openDevice:_interfaceName];
}

- (UMPCAPMirrorPort_error)openDevice:(NSString *)deviceName
{
    NSDictionary<NSString *,NSString *>*macAddrs =  [UMUtil getMacAddrs];
    NSString *s = macAddrs[deviceName];

    if(s.length == 0)
    {
        return UMPCAPMirrorPort_can_not_find_interface;
    }
    
    if(_localMacAddress.length == 0)
    {
        if(s.length > 0)
        {
            _localMacAddress =  [UMPCAPMirrorPort macAddressFromString:s];
        }
    }
    if(_localMacAddress.length == 0)
    {
        return UMPCAPMirrorPort_can_not_find_mac_address;
    }

    if(_remoteMacAddress.length == 0)
    {
        uint8_t x = _linkNumber % 254 + 1;
        uint8_t dstAddr[] = { 0x70,0xB3,0xD5,0x23,0xB0,x };
        _remoteMacAddress = [NSData dataWithBytes:dstAddr length:sizeof(dstAddr)];
    }
    _interfaceName = deviceName;
    if ((_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
    {
        if(_verbose)
        {
            NSLog(@"socket(AF_INET, SOCK_RAW, IPPROTO_RAW) fails");
        }
        return UMPCAPMirrorPort_can_not_open_socket;
    }
    
#ifdef __APPLE__
    _interfaceIndex = if_nametoindex(_interfaceName.UTF8String);
    setsockopt(_sockfd, IPPROTO_IP, IP_BOUND_IF, &_interfaceIndex, sizeof(_interfaceIndex));
#else
    const char *name = _interfaceName.UTF8String;
    setsockopt(_sockfd, SOL_SOCKET, SO_BINDTODEVICE, name, strlen(name));
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s",name);
    ioctl(_sockfd, SIOCGIFINDEX, &ifr);
    _interfaceIndex = ifr.ifr_ifru.ifru_ivalue;
#endif
    return UMPCAPMirrorPort_error_none;
}

- (NSData *)ethernetPacket:(NSData *)payload
          sourceMacAddress:(NSData *)srcMacAddr
     destinationMacAddress:(NSData *)dstMacAddr
              ethernetType:(uint16_t)ethType
{
    if((srcMacAddr.length !=6) || (dstMacAddr.length !=6))
        return NULL;
    NSMutableData *ethPacket = [[NSMutableData alloc]init];
    [ethPacket appendData:dstMacAddr];
    [ethPacket appendData:srcMacAddr];
    uint8_t h[2];
    h[0] = (ethType >> 8) & 0xFF;
    h[1] = (ethType >> 0) & 0xFF;
    [ethPacket appendBytes:h length:2];
    [ethPacket appendData:payload];
}

     c 5
    if(srcMacAddr == NULL)
    {
        srcMacAddr = _localMacAddress;
    }
}

- (NSData *)ipv4Packet:(NSData *)data
                  dscp:(uint8_t)dscp
                 flags:(uint8_t)flags
                   ttl:(uint8_t)ttl
              protocol:(uint8_t)protocol
         sourceAddress:(NSString *)srcIp
    destinationAddress:(NSString *)dstIp
                 ident:(int)ident
              fragment:(int)fragment
{
    uint8_t    header[20]; /* = length without options */
    memset(&header[0],0x00,sizeof(header));
    uint16_t totalLength = 20 * data.length;
    header[0] = 0x44; /*  , header version = 4, header length = 5*4 20 bytes */
    header[1] = dscp;
    header[2] = (totalLength >> 8) & 0xFF;
    header[3] = (totalLength >> 0) & 0xFF;
    header[4] = (ident >> 8) & 0xFF;
    header[5] = (ident >> 0) & 0xFF;
    header[6] = ((flags & 0x7) << 5) | ((fragment >> 5) & 0xFF);
    header[7] = (fragment >> 0) & 0xFF;
    header[8] = (ttl >> 0) & 0xFF;
    header[9] = (protocol >> 0) & 0xFF;
    header[10] = 0; /* header checksum */
    header[11] = 0; /* header checksum */
    NSArray *a = [srcIp componentsSeparatedByString:@"."];
    NSArray *b = [dstIp componentsSeparatedByString:@"."];
    if((a.count != 4) && (b.count != 4))
    {
        return NULL;
    }

    header[12] = (uint8_t)atoi(((NSString *)a[0]).UTF8String);
    header[13] = (uint8_t)atoi(((NSString *)a[1]).UTF8String);
    header[14] = (uint8_t)atoi(((NSString *)a[2]).UTF8String);
    header[15] = (uint8_t)atoi(((NSString *)a[3]).UTF8String);
    header[16] = (uint8_t)atoi(((NSString *)b[0]).UTF8String);
    header[17] = (uint8_t)atoi(((NSString *)b[1]).UTF8String);
    header[18] = (uint8_t)atoi(((NSString *)b[2]).UTF8String);
    header[19] = (uint8_t)atoi(((NSString *)b[3]).UTF8String);
    
    int chk = [UMPCAPPseudoConnection ip_header_checksum:header len:sizeof(header)];
    header[10] = (chk >> 8) & 0xFF; /* header checksum */
    header[11] = (chk >> 0) & 0xFF; /* header checksum */


    NSMutableData *d = [[NSMutableData alloc]init];
    [d appendBytes:&header[0] length:sizeof(header)];
    [d appendData:data];
    return d;
}

- (NSData *)tcpPacket:(NSData *)tcpPayload
           sourcePort:(uint16_t)sourcePort
      destinationPort:(uint16_t)destinationPort
       sequenceNumber:(uint32_t)seq
            ackNumber:(uint32_t)ack
                flags:(uint16_t)flags
           windowSize:(uint16_t)windowSize
        urgentPointer:(uint16_t)urgentPointer
{
    uint8_t h[20];
    h[0] = (sourcePort >> 8) & 0xFF;
    h[1] = (sourcePort >> 0) & 0xFF;
    h[2] = (destinationPort >> 8) & 0xFF;
    h[3] = (destinationPort >> 0) & 0xFF;
    
    h[4] = (seq >> 24) & 0xFF;
    h[5] = (seq >> 16) & 0xFF;
    h[6] = (seq >> 8) & 0xFF;
    h[7] = (seq >> 0) & 0xFF;

    h[8] = (ack >> 24) & 0xFF;
    h[9] = (ack >> 16) & 0xFF;
    h[10] = (ack >> 8) & 0xFF;
    h[11] = (ack >> 0) & 0xFF;
    h[12] = ((sizeof(h) / 4) << 4) |  ((flags >>8) & 0x0F);
    h[13] = ((flags >>0) & 0xFF);
    h[14] = ((windowSize >>8) & 0xFF);
    h[15] = ((windowSize >>0) & 0xFF);
    h[16] = 0;
    h[17] = 0;
    h[18] = ((urgentPointer >>8) & 0xFF);
    h[19] = ((urgentPointer >>0) & 0xFF);
    int tcpChecksum = [UMPCAPMirrorPort layer4_checksum:tcpPayload headerPtr:&h[0] headerLen:sizeof(h)];
    h[16] = ((tcpChecksum >>8) & 0xFF);
    h[17] = ((tcpChecksum >>0) & 0xFF);
    NSMutableData *tcpPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [tcpPacket appendData:tcpPayload];
    return tcpPacket;
}

- (NSData *)udpPacket:(NSData *)udpPayload
           sourcePort:(uint16_t)sourcePort
      destinationPort:(uint16_t)destinationPort
           sequenceNumber:(uint32_t)seq
            ackNumber:(uint32_t)ack
                flags:(uint16_t)flags
           windowSize:(uint16_t)windowSize
           urgentPointer:(uint16_t)urgentPointer
{

    uint8_t h[8];
    int length = (int)udpPayload.length + 8;
    h[0] = (sourcePort >> 8) & 0xFF;
    h[1] = (sourcePort >> 0) & 0xFF;
    h[2] = (destinationPort >> 8) & 0xFF;
    h[3] = (destinationPort >> 0) & 0xFF;
    h[4] = (length >> 8) & 0xFF;
    h[5] = (length >> 0) & 0xFF;
    h[6] = 0;
    h[7] = 0;
    int udpChecksum = [UMPCAPMirrorPort layer4_checksum:udpPayload headerPtr:&h[0] headerLen:sizeof(h)];
    h[6] = (udpChecksum >> 8) & 0xFF;
    h[7] = (udpChecksum >> 0) & 0xFF;
    NSMutableData *udpPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [udpPacket appendData:udpPayload];
    return udpPacket;
}

+ (uint16_t)  layer4_checksum:(NSData *)payload headerPtr:(uint8_t *)h headerLen:(int)headerLen
{
    uint32_t acc = 0;
    uint16_t src;

    int i;
    for(i=0;i<headerLen;i += 2)
    {
        acc += (h[i] << 8)  | (h[i+1]);
    }

    for(i=0;i<headerLen;i += 2)
    {
        acc += (h[i] << 8)  | (h[i+1]);
    }

    /* dataptr may be at odd or even addresses */

    const uint8_t *octetptr = payload.bytes;
    int len = (int)payload.length;
    while (len > 1)
    {
        /* declare first octet as most significant
         thus assume network order, ignoring host order */
        src = (*octetptr) << 8;
        octetptr++;
        /* declare second octet as least significant */
        src |= (*octetptr);
        octetptr++;
        acc += src;
        len -= 2;
    }
    if (len > 0)
    {
        /* accumulate remaining octet */
        src = (*octetptr) << 8;
        acc += src;
    }
    /* add deferred carry bits */
    acc = (acc >> 16) + (acc & 0x0000ffffUL);
    if ((acc & 0xffff0000UL) != 0)
    {
        acc = (acc >> 16) + (acc & 0x0000ffffUL);
    }
    return 0xFFFF ^ acc;
}

@end
