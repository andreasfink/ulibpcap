//
//  UMPCAPPseudoConnection.m
//  ulibpcap
//
//  Created by Andreas Fink on 26.02.18.
//  Copyright © 2018 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import "UMPCAPPseudoConnection.h"

/* this object holds data for filling in pseudo data pseudo connection above IP */

@implementation UMPCAPPseudoConnection

-(UMPCAPPseudoConnection *)init
{
    self = [super init];
    if(self)
    {
        uint8_t srcAddr[] = { 1,0,0,0,0,0 };
        uint8_t dstAddr[] = { 7,7,7,7,7,7 };
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
    }
    return self;
}

- (BOOL)tcap
{
    if(_protocol==6)
        return YES;
    return NO;
}


- (NSData *)localToRemoteEthernetHeader
{
    NSMutableData *header = [[NSMutableData alloc]init];

    /* ETHERNET HEADER */
    [header appendData:_remoteMacAddress];
    [header appendData:_localMacAddress];
    [header appendData:_etherType];

    return header;
}

- (NSData *)remoteToLocalEthernetHeader;
{
    NSMutableData *header = [[NSMutableData alloc]init];
    
    /* ETHERNET HEADER */
    [header appendData:_localMacAddress];
    [header appendData:_remoteMacAddress];
    [header appendData:_etherType];
    return header;
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
    uint8_t h[20];
    
    h[0] = 0x45; /*version 4 , header length 5 */
    h[1] = 0x00; /* differentiated services  / type of service */
    h[2] = (packetLen >> 8) & 0xFF;
    h[3] = (packetLen >> 0) & 0xFF;
    h[4] = (_sequenceCounter >>8) & 0xFF;
    h[5] = (_sequenceCounter >>0) & 0xFF;
    h[6] = 0x02; /* flags "dont fragment" */
    h[7] = 0x00; /* fragment offset */
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
    
    int i;
    int chk = 0;
    for(i=0;i<30;i+=2)
    {
        chk += 0 - ((h[i] <<8) | h[i+1]);
    }
    chk = 0-chk;
    
    /*
     The checksum field is the 16 bit one's complement of the one's
     complement sum of all 16 bit words in the header.  For purposes of
     computing the checksum, the value of the checksum field is zero.
     */
    
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
    uint8_t sourcePort;
    uint8_t destinationPort;
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
    int tcpChecksum = 0;
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
    h[16] = ((tcpChecksum >>8) & 0xFF);
    h[17] = ((tcpChecksum >>0) & 0xFF);
    h[18] = ((urgentPointer >>8) & 0xFF);
    h[19] = ((urgentPointer >>0) & 0xFF);
    _tcpSeqNumber++;
    _tcpAckNumber++;
    NSMutableData *tcpPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [tcpPacket appendData:tcpPayload];
    NSData *packet =  [self ipv4Packet:tcpPacket inbound:inbound];
    return packet;
}

- (NSData *)udpPacket:(NSData *)udpPayload inbound:(BOOL)inbound
{
    uint8_t sourcePort;
    uint8_t destinationPort;
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
    int udpChecksum = 0;
    h[0] = (sourcePort >> 8) & 0xFF;
    h[1] = (sourcePort >> 0) & 0xFF;
    h[2] = (destinationPort >> 8) & 0xFF;
    h[3] = (destinationPort >> 0) & 0xFF;
    
    h[4] = (length >> 8) & 0xFF;
    h[5] = (length >> 0) & 0xFF;
    h[6] = (udpChecksum >> 8) & 0xFF;
    h[7] = (udpChecksum >> 0) & 0xFF;

    NSMutableData *udpPacket = [[NSMutableData alloc]initWithBytes:h length:sizeof(h)];
    [udpPacket appendData:udpPayload];
    NSData *packet =  [self ethernetPacket:udpPacket inbound:inbound];
    return packet;
}

@end
