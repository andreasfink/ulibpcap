//
//  UMPCAPPseudoConnection.h
//  ulibpcap
//
//  Created by Andreas Fink on 26.02.18.
//  Copyright © 2018 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>

typedef enum UMPCAPPseudoConnection_ip_protocol
{
    UMPCAPPseudoConnection_ip_protocol_tcp = 6,
    UMPCAPPseudoConnection_ip_protocol_udp = 17,
} UMPCAPPseudoConnection_ip_protocol;

@interface UMPCAPPseudoConnection : UMObject
{
    NSData *_localMacAddress;
    NSData *_remoteMacAddress;
    NSData *_etherType;
    NSString *_localIP;
    NSString *_remoteIP;
    int _localPort;
    int _remotePort;
    UMPCAPPseudoConnection_ip_protocol _protocol;
    uint16_t _sequenceCounter;
    uint16_t _tcpSeqNumber;
    uint16_t _tcpAckNumber;

}

@property(readwrite,strong,atomic)  NSData *localMacAddress;
@property(readwrite,strong,atomic)  NSData *remoteMacAddress;
@property(readwrite,strong,atomic)  NSData *etherType;
@property(readwrite,strong,atomic)  NSString *localIP;
@property(readwrite,strong,atomic)  NSString *remoteIP;
@property(readwrite,assign,atomic)  int localPort;
@property(readwrite,assign,atomic)  int remotePort;
@property(readwrite,assign,atomic)  UMPCAPPseudoConnection_ip_protocol protocol;

- (NSData *)ethernetPacket:(NSData *)payload inbound:(BOOL)inbound;
- (NSData *)ipv4Packet:(NSData *)ipPayload inbound:(BOOL)inbound;
- (NSData *)tcpPacket:(NSData *)tcpPayload inbound:(BOOL)inbound;
- (NSData *)udpPacket:(NSData *)udpPayload inbound:(BOOL)inbound;

@end
