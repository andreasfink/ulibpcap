//
//  UMPCAPPseudoConnection.h
//  ulibpcap
//
//  Created by Andreas Fink on 26.02.18.
//  Copyright © 2018 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>

typedef enum UMPCAP_MTP2_AnnexA
{
    UMPCAP_MTP2_ANNEX_A_NOT_USED = 0,
    UMPCAP_MTP2_ANNEX_A_USED = 1,
    UMPCAP_MTP2_ANNEX_A_USED_UNKNOWN = 2,
} UMPCAP_MTP2_AnnexA;

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
    int _linkNumber;
}

-(UMPCAPPseudoConnection *)initForLinkNumber:(int)link; /* adding a link number 0...254 will increase the mac address accordingly for ethernet framing. For mtp2 framing, it will set the link number into the pseudo header */

@property(readwrite,assign,atomic)  int type;
@property(readwrite,strong,atomic)  NSData *localMacAddress;
@property(readwrite,strong,atomic)  NSData *remoteMacAddress;
@property(readwrite,strong,atomic)  NSData *etherType;
@property(readwrite,strong,atomic)  NSString *localIP;
@property(readwrite,strong,atomic)  NSString *remoteIP;
@property(readwrite,assign,atomic)  int localPort;
@property(readwrite,assign,atomic)  int remotePort;
@property(readwrite,assign,atomic)  UMPCAPPseudoConnection_ip_protocol protocol;
@property(readwrite,assign,atomic)  int linkNumber;

- (NSData *)ethernetPacket:(NSData *)payload inbound:(BOOL)inbound;
- (NSData *)ipv4Packet:(NSData *)ipPayload inbound:(BOOL)inbound;
- (NSData *)tcpPacket:(NSData *)tcpPayload inbound:(BOOL)inbound;
- (NSData *)udpPacket:(NSData *)udpPayload inbound:(BOOL)inbound;

+ (NSData *)mtp2PacketWithPseudoHeader:(NSData *)payload
                               inbound:(BOOL)inbound
                                  link:(int)link
                               annex_a:(UMPCAP_MTP2_AnnexA)annex_a;

- (NSData *)mtp2PacketWithPseudoHeader:(NSData *)payload inbound:(BOOL)inbound;

@end
