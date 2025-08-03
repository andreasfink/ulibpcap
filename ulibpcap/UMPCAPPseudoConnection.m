//
//  UMPCAPPseudoConnection.m
//  ulibpcap
//
//  Created by Andreas Fink on 26.02.18.
//  Copyright © 2018 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import "UMPCAPPseudoConnection.h"
#import <pcap/pcap.h>

/* this object holds data for filling in pseudo data pseudo connection above IP */

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
        _payloadProtocolIdentifier = 5; /* SCTP_PROTOCOL_IDENTIFIER_M2PA */
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
    uint8_t commonMessageHeader[17];
    NSInteger len = payload.length + sizeof(commonMessageHeader);
    commonMessageHeader[0] = 1; /* version 1*/
    commonMessageHeader[1] = 0; /* spare */
    commonMessageHeader[2] = 11; /* message class */
    commonMessageHeader[3] = 1; /* message type user Data) */
    commonMessageHeader[4] =  ((len >> 24) & 0xFF);  /* len */
    commonMessageHeader[5]  = ((len >> 16) & 0xFF);  /* len */
    commonMessageHeader[6]  = ((len >>  8) & 0xFF);  /* len */
    commonMessageHeader[7]  = ((len >>  0) & 0xFF);/* len */
    commonMessageHeader[8] =  0;  /* FSN */
    commonMessageHeader[9]  = 0;  /* FSN */
    commonMessageHeader[10]  = 0;  /* FSN */
    commonMessageHeader[11]  = 100;/* FSN */
    commonMessageHeader[12]  = 0;  /* BSN*/
    commonMessageHeader[13]  = 0;  /* BSN*/
    commonMessageHeader[14] = 0;  /* BSN*/
    commonMessageHeader[15] = 200;/* BSN*/
    commonMessageHeader[16] = 0;/* priority*/
    NSMutableData *data = [NSMutableData dataWithBytes:&commonMessageHeader length:sizeof(commonMessageHeader)];
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
- (NSData *)ipv4Packet:(NSData *)ipPayload protocol:(int)protocol inbound:(BOOL)inbound
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
    h[9] = protocol;
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
    int chk = [UMPCAPPseudoConnection ip_header_checksum:h len:sizeof(h)];
    h[10] = (chk >> 8) & 0xFF; /* header checksum */
    h[11] = (chk >> 0) & 0xFF; /* header checksum */
    
    _sequenceCounter++;
    
    NSMutableData *ipPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [ipPacket appendData:ipPayload];
    return ipPacket;
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


    int tcpChecksum = [self layer4_checksum:tcpPayload
                                  headerPtr:&h[0]
                                  headerLen:sizeof(h)
                                    inbound:inbound];
    h[16] = ((tcpChecksum >>8) & 0xFF);
    h[17] = ((tcpChecksum >>0) & 0xFF);

    _tcpSeqNumber++;
    _tcpAckNumber++;
    NSMutableData *tcpPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [tcpPacket appendData:tcpPayload];
    NSData *packet =  [self ipv4Packet:tcpPacket protocol:UMPCAPPseudoConnection_ip_protocol_tcp inbound:inbound];
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


    int udpChecksum = [self layer4_checksum:udpPayload
                                  headerPtr:&h[0]
                                  headerLen:sizeof(h)
                                    inbound:inbound];
    h[6] = (udpChecksum >> 8) & 0xFF;
    h[7] = (udpChecksum >> 0) & 0xFF;

    NSMutableData *udpPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [udpPacket appendData:udpPayload];
    NSData *packet =  [self ipv4Packet:udpPacket protocol:UMPCAPPseudoConnection_ip_protocol_udp inbound:inbound];
    return packet;
}

- (NSData *)sctpPacket:(NSData *)sctpPayload inbound:(BOOL)inbound
{
    NSMutableData *p = [[NSMutableData alloc]init];
    int srcPort;
    int dstPort;
    if(inbound)
    {
        srcPort = _remotePort;
        dstPort = _localPort;
    }
    else
    {
        srcPort = _localPort;
        dstPort = _remotePort;
    }
    int payloadProtocolIdentifier = _payloadProtocolIdentifier;

    int verificationTag = 0;
    int checksum = 0;
    [p appendByte: (srcPort>>8) & 0xFF];
    [p appendByte: (srcPort>>0) & 0xFF];
    [p appendByte: (dstPort>>8) & 0xFF];
    [p appendByte: (dstPort>>0) & 0xFF];
    [p appendByte: (verificationTag>>24) & 0xFF];
    [p appendByte: (verificationTag>>16) & 0xFF];
    [p appendByte: (verificationTag>>8) & 0xFF];
    [p appendByte: (verificationTag>>0) & 0xFF];
    [p appendByte: (checksum>>24) & 0xFF];
    [p appendByte: (checksum>>16) & 0xFF];
    [p appendByte: (checksum>>8) & 0xFF];
    [p appendByte: (checksum>>0) & 0xFF];
    /* encoding DATA chunk */
    [p appendByte:0]; /* chunk type 0 = DATA */
    [p appendByte:0x03]; /* chunk flags 0  */
    int len = (int)sctpPayload.length;
    len = len + 16;
    [p appendByte: (len>>8) & 0xFF]; /* len  */
    [p appendByte: (len>>0) & 0xFF]; /* len  */
    [p appendByte: 0]; /* TSN  */
    [p appendByte: 0]; /* TSN  */
    [p appendByte: 0]; /* TSN  */
    [p appendByte: 0]; /* TSN  */
    [p appendByte: 0]; /* stream identifier  */
    [p appendByte: 1]; /* we assume M2PA_STREAM_USERDATA */
    [p appendByte: 0]; /* stream sequence  */
    [p appendByte: 0];
    [p appendByte:(payloadProtocolIdentifier >> 24) & 0xFF];
    [p appendByte:(payloadProtocolIdentifier >> 16) & 0xFF];
    [p appendByte:(payloadProtocolIdentifier >> 8)  & 0xFF];
    [p appendByte:(payloadProtocolIdentifier >> 0)  & 0xFF];
    [p appendData:sctpPayload];
    int remaining = (len % 4);
    switch(remaining)
    {
        case 0:
            break;
        case 1:
            [p appendByte: 0];
            [p appendByte: 0];
            [p appendByte: 0];
            break;
        case 2:
            [p appendByte: 0];
            [p appendByte: 0];
            break;
        case 3:
            [p appendByte: 0];
            break;
    }
    return p;
}

- (NSData *)syslogPacket:(NSString *)str
{
    NSData *udpPayload = [self encodeSyslogPacket:str];
    
    uint16_t sourcePort = 514; /* syslog port*/
    uint16_t destinationPort = 514;
    uint8_t h_udp[8];
    int length = (int)udpPayload.length + 8;
    h_udp[0] = (sourcePort >> 8) & 0xFF;
    h_udp[1] = (sourcePort >> 0) & 0xFF;
    h_udp[2] = (destinationPort >> 8) & 0xFF;
    h_udp[3] = (destinationPort >> 0) & 0xFF;
    h_udp[4] = (length >> 8) & 0xFF;
    h_udp[5] = (length >> 0) & 0xFF;
    h_udp[6] = 0;
    h_udp[7] = 0;
    int udpChecksum = [UMPCAPPseudoConnection layer4_checksum:udpPayload
                                                     sourceIp:@"127.0.0.1"
                                                       destIp:@"127.0.0.1"
                                               protocolNumber:IPPROTO_UDP
                                                    headerPtr:&h_udp[0]
                                                    headerLen:sizeof(h_udp)];
    h_udp[6] = (udpChecksum >> 8) & 0xFF;
    h_udp[7] = (udpChecksum >> 0) & 0xFF;
    NSMutableData *udpPacket = [[NSMutableData alloc]initWithBytes:h_udp length:sizeof(h_udp)];
    [udpPacket appendData:udpPayload];
    
    int payloadLen = (int)udpPacket.length;
    int packetLen = payloadLen + 20;
    int identification = 0;
    int flags = 0x02; /* flags "dont fragment" */
    int fragmentOffset = 0;
    uint8_t h_ip[20];
    h_ip[0] = 0x45; /*version 4 , header length 5 */
    h_ip[1] = 0x00; /* differentiated services  / type of service */
    h_ip[2] = (packetLen >> 8) & 0xFF;
    h_ip[3] = (packetLen >> 0) & 0xFF;
    h_ip[4] = (identification >>8) & 0xFF;
    h_ip[5] = (identification >>0) & 0xFF;
    h_ip[6] = ((flags <<6) & 0xFF) | (((fragmentOffset & 0x3F) >> 8) & 0xFF);
    h_ip[7] = (fragmentOffset & 0xFF); /* fragment offset */
    h_ip[8] = 64; /* time to live */
    h_ip[9] = UMPCAPPseudoConnection_ip_protocol_udp;
    h_ip[10] = 0; /* header checksum to be calculated later */
    h_ip[11] = 0; /* header checksum to be calculated later */
    h_ip[12] = 127;
    h_ip[13] = 0;
    h_ip[14] = 0;
    h_ip[15] = 1;
    h_ip[16] = 127;
    h_ip[17] = 0;
    h_ip[18] = 0;
    h_ip[19] = 1;
    int chk = [UMPCAPPseudoConnection ip_header_checksum:h_ip len:sizeof(h_ip)];
    h_ip[10] = (chk >> 8) & 0xFF; /* header checksum */
    h_ip[11] = (chk >> 0) & 0xFF; /* header checksum */
    _sequenceCounter++;
    NSMutableData *ipPacket = [[NSMutableData alloc]initWithBytes:h_ip length:sizeof(h_ip)];
    [ipPacket appendData:udpPacket];
    NSData *packet =  [self ethernetPacket:ipPacket inbound:YES];
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

- (uint16_t)  layer4_checksum:(NSData *)payload
                    headerPtr:(uint8_t *)headerPtr
                    headerLen:(int)headerLen
                      inbound:(BOOL)inbound
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
    
    return [UMPCAPPseudoConnection layer4_checksum:payload
                                          sourceIp:sourceIP
                                            destIp:destinationIP
                                    protocolNumber:_protocol
                                         headerPtr:headerPtr
                                         headerLen:headerLen];
}

+ (uint16_t)  layer4_checksum:(NSData *)payload
                     sourceIp:(NSString *)sourceIP
                       destIp:(NSString *)destinationIP
               protocolNumber:(int)protocol
                    headerPtr:(uint8_t *)headerPtr
                    headerLen:(int)headerLen
{
    uint8_t h[12];
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
    h[9] = protocol;
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

    
    NSData *paddedData = payload;
    if((payload.length % 2)==1)
    {
        NSMutableData *p = [payload mutableCopy];
        [p appendByte:0];
        paddedData = p;
    }
    
    const uint8_t *octetptr = paddedData.bytes;
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




+ (uint16_t) ip_header_checksum:(const void *)dataptr len:(int)len;
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

- (NSData *)encodeSyslogPacket:(NSString *)message
{
    int prival = 132;
    NSString *pri = [NSString stringWithFormat:@"<%d>",prival];
    NSString *version = @"1";
    NSString *sp = @" ";
    NSString *msg = message;
    NSString *structured_data = @"";
    NSString *hostname=@"";
    NSString *timestamp=@"";
    NSString *procid=@"";
    NSString *msgid=@"";
    NSString *appname=@"";
    NSString *header = [NSString stringWithFormat:@"%@%@%@%@%@%@%@%@%@%@%@",
                        pri,version,sp,timestamp,sp,hostname,sp,appname,procid,sp,msgid];
    NSString *syslog_msg = [NSString stringWithFormat:@"%@%@%@%@%@",header,sp,structured_data,sp,msg];
    NSData *data = [syslog_msg dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:YES];
    return data;
}

@end
