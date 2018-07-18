//
//  UMPCAPPseudoConnection.m
//  ulibpcap
//
//  Created by Andreas Fink on 26.02.18.
//  Copyright © 2018 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import "UMPCAPPseudoConnection.h"

/* this object holds data for filling in pseudo data pseudo connection above IP */

static uint16_t  ip_header_checksum(const void *dataptr, int len);

@implementation UMPCAPPseudoConnection

-(UMPCAPPseudoConnection *)init
{
    return [self initForLinkNumber:0];
}

-(UMPCAPPseudoConnection *)initForLinkNumber:(int)link
{
    self = [super init];
    if(self)
    {
        uint8_t srcAddr[] = { 0x70,0xB3,0xD5,0x23,0xB0,0x00 };
        uint8_t x = link % 254 + 1;
        uint8_t dstAddr[] = { 0x70,0xB3,0xD5,0x23,0xB0,x };
        uint8_t etherType[] = { 0x08, 0x00 };
        _localMacAddress = [NSData dataWithBytes:srcAddr length:sizeof(srcAddr)];
        _remoteMacAddress = [NSData dataWithBytes:dstAddr length:sizeof(dstAddr)];
        _etherType = [NSData dataWithBytes:etherType length:sizeof(etherType)];
        _localIP = @"127.0.0.1";
        _remoteIP = @"127.0.0.2";
        _localPort = 80;
        _remotePort = 3000;
        _protocol = 6; /* TCP */
        _sequenceCounter = 0;
        _tcpSeqNumber = 100;
        _tcpAckNumber = 99;
        _linkNumber = link;
    }
    return self;
}

- (NSData *)mtp2PacketWithPseudoHeader:(NSData *)payload inbound:(BOOL)inbound
{
    return [UMPCAPPseudoConnection mtp2PacketWithPseudoHeader:payload
                                                      inbound:inbound
                                                         link:_linkNumber
                                                      annex_a:UMPCAP_MTP2_ANNEX_A_USED_UNKNOWN];
}

+ (NSData *)mtp2PacketWithPseudoHeader:(NSData *)payload
                               inbound:(BOOL)inbound
                                  link:(int)link
                               annex_a:(UMPCAP_MTP2_AnnexA)annex_a
{
    uint8_t header[4];
    header[0] = inbound ? 0 : 1;
    header[1] = annex_a;
    header[2] = link & 0xFF;
    header[3] = (link & 0xFF00)>> 8;

    NSMutableData *data = [NSMutableData dataWithBytes:&header length:sizeof(header)];
    [data appendData:payload];
    return data;
}

- (NSData *)ethernetPacket:(NSData *)payload inbound:(BOOL)inbound
{
    NSMutableData *header = [[NSMutableData alloc]init];
    if(inbound)
    {
        [header appendData:_localMacAddress];
        [header appendData:_remoteMacAddress];
    }
    else
    {
        [header appendData:_remoteMacAddress];
        [header appendData:_localMacAddress];
    }
    [header appendData:_etherType];
    [header appendData:payload];
    return header;
}

/* from https://www.ietf.org/rfc/rfc791.txt
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
- (NSData *)ipv4Packet:(NSData *)ipPayload inbound:(BOOL)inbound
{
    NSString *sourceIP;
    NSString *destinationIP;
    if(inbound)
    {
        sourceIP = _remoteIP;
        destinationIP = _localIP;
    }
    else
    {
        sourceIP = _localIP;
        destinationIP = _remoteIP;
    }
    
    int payloadLen = (int)ipPayload.length;
    int packetLen = payloadLen + 20;
    int identification = 0;
    int flags = 0x02; /* flags "dont fragment" */
    int fragmentOffset = 0;
    uint8_t h[20];
    
    h[0] = 0x45; /*version 4 , header length 5 */
    h[1] = 0x00; /* differentiated services  / type of service */
    h[2] = (packetLen >> 8) & 0xFF;
    h[3] = (packetLen >> 0) & 0xFF;
    h[4] = (identification >>8) & 0xFF;
    h[5] = (identification >>0) & 0xFF;
    h[6] = ((flags <<6) & 0xFF) | (((fragmentOffset & 0x3F) >> 8) & 0xFF);
    h[7] = (fragmentOffset & 0xFF); /* fragment offset */
    h[8] = 64; /* time to live */
    h[9] = _protocol;
    h[10] = 0; /* header checksum to be calculated later */
    h[11] = 0; /* header checksum to be calculated later */
    
    int a = 0;
    int b = 0;
    int c = 0;
    int d = 0;
    
    if(sourceIP)
    {
        sscanf(sourceIP.UTF8String,"%d.%d.%d.%d",&a,&b,&c,&d);
    }
    h[12] = a;
    h[13] = b;
    h[14] = c;
    h[15] = d;
    
    a = 255;
    b = 255;
    c = 255;
    d = 255;
    
    if(destinationIP)
    {
        sscanf(destinationIP.UTF8String,"%d.%d.%d.%d",&a,&b,&c,&d);
    }
    h[16] = a;
    h[17] = b;
    h[18] = c;
    h[19] = d;
    

    /*
     The checksum field is the 16 bit one's complement of the one's
     complement sum of all 16 bit words in the header.  For purposes of
     computing the checksum, the value of the checksum field is zero.
     */
    int chk = ip_header_checksum(h,sizeof(h));


    h[10] = (chk >> 8) & 0xFF; /* header checksum */
    h[11] = (chk >> 0) & 0xFF; /* header checksum */
    
    _sequenceCounter++;
    
    NSMutableData *ipPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [ipPacket appendData:ipPayload];
    NSData *packet =  [self ethernetPacket:ipPacket inbound:inbound];
    return packet;
}



/*
 from https://www.ietf.org/rfc/rfc793.txt
 
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Source Port          |       Destination Port        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Sequence Number                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Acknowledgment Number                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Data |           |U|A|P|R|S|F|                               |
 | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 |       |           |G|K|H|T|N|N|                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Checksum            |         Urgent Pointer        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             data                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


- (NSData *)tcpPacket:(NSData *)tcpPayload inbound:(BOOL)inbound
{
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint8_t h[20];
    if(inbound)
    {
        sourcePort = _remotePort;
        destinationPort = _localPort;
    }
    else
    {
        sourcePort = _localPort;
        destinationPort = _remotePort;
    }
    int flags = 0x018; /* flags PSH, ACK */
    int windowSize = 500;
    int urgentPointer=0;
;
    h[0] = (sourcePort >> 8) & 0xFF;
    h[1] = (sourcePort >> 0) & 0xFF;
    h[2] = (destinationPort >> 8) & 0xFF;
    h[3] = (destinationPort >> 0) & 0xFF;
    
    h[4] = (_tcpSeqNumber >> 24) & 0xFF;
    h[5] = (_tcpSeqNumber >> 16) & 0xFF;
    h[6] = (_tcpSeqNumber >> 8) & 0xFF;
    h[7] = (_tcpSeqNumber >> 0) & 0xFF;

    h[8] = (_tcpAckNumber >> 24) & 0xFF;
    h[9] = (_tcpAckNumber >> 16) & 0xFF;
    h[10] = (_tcpAckNumber >> 8) & 0xFF;
    h[11] = (_tcpAckNumber >> 0) & 0xFF;
    h[12] = ((sizeof(h) / 4) << 4) |  ((flags >>8) & 0x0F);
    h[13] = ((flags >>0) & 0xFF);
    h[14] = ((windowSize >>8) & 0xFF);
    h[15] = ((windowSize >>0) & 0xFF);
    h[16] = 0;
    h[17] = 0;
    h[18] = ((urgentPointer >>8) & 0xFF);
    h[19] = ((urgentPointer >>0) & 0xFF);


    int tcpChecksum = [self layer4_checksum:tcpPayload headerPtr:&h[0] headerLen:sizeof(h) inbound:inbound];
    h[16] = ((tcpChecksum >>8) & 0xFF);
    h[17] = ((tcpChecksum >>0) & 0xFF);

    _tcpSeqNumber++;
    _tcpAckNumber++;
    NSMutableData *tcpPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [tcpPacket appendData:tcpPayload];
    NSData *packet =  [self ipv4Packet:tcpPacket inbound:inbound];
    return packet;
}

- (NSData *)udpPacket:(NSData *)udpPayload inbound:(BOOL)inbound
{
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint8_t h[8];
    int length = (int)udpPayload.length + 8;
    if(inbound)
    {
        sourcePort = _remotePort;
        destinationPort = _localPort;
    }
    else
    {
        sourcePort = _localPort;
        destinationPort = _remotePort;
    }

    h[0] = (sourcePort >> 8) & 0xFF;
    h[1] = (sourcePort >> 0) & 0xFF;
    h[2] = (destinationPort >> 8) & 0xFF;
    h[3] = (destinationPort >> 0) & 0xFF;
    
    h[4] = (length >> 8) & 0xFF;
    h[5] = (length >> 0) & 0xFF;

    h[6] = 0;
    h[7] = 0;

    int udpChecksum =  [self layer4_checksum:udpPayload headerPtr:&h[0] headerLen:sizeof(h) inbound:inbound];

    h[6] = (udpChecksum >> 8) & 0xFF;
    h[7] = (udpChecksum >> 0) & 0xFF;

    NSMutableData *udpPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [udpPacket appendData:udpPayload];
    NSData *packet =  [self ipv4Packet:udpPacket inbound:inbound];
    return packet;
}


/*
Checksum:  16 bits

The checksum field is the 16 bit one's complement of the one's
complement sum of all 16 bit words in the header and text.  If a
segment contains an odd number of header and text octets to be
checksummed, the last octet is padded on the right with zeros to
form a 16 bit word for checksum purposes.  The pad is not
transmitted as part of the segment.  While computing the checksum,
the checksum field itself is replaced with zeros.

The checksum also covers a 96 bit pseudo header conceptually

prefixed to the TCP header.  This pseudo header contains the Source
Address, the Destination Address, the Protocol, and TCP length.
This gives the TCP protection against misrouted segments.  This
information is carried in the Internet Protocol and is transferred
across the TCP/Network interface in the arguments or results of
calls by the TCP on the IP.

+--------+--------+--------+--------+
|           Source Address          |
+--------+--------+--------+--------+
|         Destination Address       |
+--------+--------+--------+--------+
|  zero  |  PTCL  |    TCP Length   |
+--------+--------+--------+--------+

The TCP Length is the TCP header length plus the data length in
octets (this is not an explicitly transmitted quantity, but is
        computed), and it does not count the 12 octets of the pseudo
header.
*/

- (uint16_t)  layer4_checksum:(NSData *)payload headerPtr:(uint8_t *)headerPtr headerLen:(int)headerLen inbound:(BOOL)inbound
{
    uint8_t h[12];
    NSString *sourceIP;
    NSString *destinationIP;
    if(inbound)
    {
        sourceIP = _remoteIP;
        destinationIP = _localIP;
    }
    else
    {
        sourceIP = _localIP;
        destinationIP = _remoteIP;
    }

    int payloadLen = (int)payload.length;
    int packetLen = payloadLen + headerLen;
    int a = 0;
    int b = 0;
    int c = 0;
    int d = 0;

    if(sourceIP)
    {
        sscanf(sourceIP.UTF8String,"%d.%d.%d.%d",&a,&b,&c,&d);
    }
    h[0] = a;
    h[1] = b;
    h[2] = c;
    h[3] = d;

    a = 255;
    b = 255;
    c = 255;
    d = 255;

    if(destinationIP)
    {
        sscanf(destinationIP.UTF8String,"%d.%d.%d.%d",&a,&b,&c,&d);
    }
    h[4] = a;
    h[5] = b;
    h[6] = c;
    h[7] = d;

    h[8] = 0;
    h[9] = _protocol;
    h[10] = (packetLen >>8) & 0xFF;
    h[11] = (packetLen >>0) & 0xFF;

    uint32_t acc = 0;
    uint16_t src;

    int i;
    for(i=0;i<12;i += 2)
    {
        acc += (h[i] << 8)  | (h[i+1]);
    }

    for(i=0;i<headerLen;i += 2)
    {
        acc += (headerPtr[i] << 8)  | (headerPtr[i+1]);
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

/*
 from https://www.ietf.org/rfc/rfc793.txt

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |          Source Port          |       Destination Port        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                        Sequence Number                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Acknowledgment Number                      |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Data |           |U|A|P|R|S|F|                               |
 | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
 |       |           |G|K|H|T|N|N|                               |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           Checksum            |         Urgent Pointer        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                             data                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */


@end


static uint16_t  ip_header_checksum(const void *dataptr, int len)
{
    uint32_t acc;
    uint16_t src;
    const uint8_t *octetptr;

    acc = 0;
    /* dataptr may be at odd or even addresses */
    octetptr = (const uint8_t *)dataptr;
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

