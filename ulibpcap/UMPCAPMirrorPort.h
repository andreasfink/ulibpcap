//
//  UMPCAPMirrorPort.h
//  ulibpcap
//
//  Created by Andreas Fink on 09.05.22.
//  Copyright © 2022 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>
#import <pcap/pcap.h>

typedef enum UMPCAPMirrorPort_error
{
    UMPCAPMirrorPort_error_none                = 0,
    UMPCAPMirrorPort_can_not_open_socket       = 1,
    UMPCAPMirrorPort_can_not_find_interface    = 2,
    UMPCAPMirrorPort_can_not_find_mac_address  = 3,
} UMPCAPMirrorPort_error;


@interface UMPCAPMirrorPort : UMObject
{
    NSString    *_name;
    NSString    *_interfaceName;
    int         _interfaceIndex;
    int         _linkNumber;
    NSData      *_localMacAddress;
    NSData      *_remoteMacAddress;
    BOOL        _verbose;
    int         _sockfd;
    int         _snaplen;
    int         _promisc;
    int         _to_ms;
    pcap_t*     _pcap;
    NSString    *_lastError;
}


@property(readwrite,strong,atomic)  NSString    *name;
@property(readwrite,strong,atomic)  NSString    *interfaceName;
@property(readwrite,strong,atomic)  NSString    *lastError;
@property(readwrite,assign,atomic)  int         interfaceIndex;
@property(readwrite,assign,atomic)  int         linkNumber;
@property(readwrite,strong,atomic)  NSData      *localMacAddress;
@property(readwrite,strong,atomic)  NSData      *remoteMacAddress;
@property(readwrite,assign,atomic)  BOOL        verbose;
@property(readwrite,assign,atomic)  int         sockfd;
@property(readwrite,assign,atomic)  int         snaplen;
@property(readwrite,assign,atomic)  int         promisc;
@property(readwrite,assign,atomic)  int         to_ms;



- (UMPCAPMirrorPort *)initWithLinkNumber:(int)linkNumber;
+ (NSData *)macAddressFromString:(NSString *)in;
- (void)setConfig:(NSDictionary *)dict;

- (UMPCAPMirrorPort_error)openDevice;
- (UMPCAPMirrorPort_error)openDevice:(NSString *)deviceName;
- (void)close;

- (int)writeEthernetPacket:(NSData *)payload;

+ (NSData *)ethernetPacket:(NSData *)payload
          sourceMacAddress:(NSData *)srcMacAddr
     destinationMacAddress:(NSData *)dstMacAddr
              ethernetType:(uint16_t)ethType;

+ (NSData *)ipv4Packet:(NSData *)data
                  dscp:(uint8_t)dscp
                 flags:(uint8_t)flags
                   ttl:(uint8_t)ttl
              protocol:(uint8_t)protocol
         sourceAddress:(NSString *)srcIp
    destinationAddress:(NSString *)dstIp
                 ident:(int)ident
              fragment:(int)fragment;

+ (NSData *)tcpPacket:(NSData *)tcpPayload
        sourceAddress:(NSString *)srcIp
   destinationAddress:(NSString *)dstIp
           sourcePort:(uint16_t)sourcePort
      destinationPort:(uint16_t)destinationPort
       sequenceNumber:(uint32_t)seq
            ackNumber:(uint32_t)ack
                flags:(uint16_t)flags
           windowSize:(uint16_t)windowSize
        urgentPointer:(uint16_t)urgentPointer
       fragmentLength:(uint16_t)fragmentLength;


+ (NSData *)udpPacket:(NSData *)udpPayload
        sourceAddress:(NSString *)srcIp
   destinationAddress:(NSString *)dstIp
           sourcePort:(uint16_t)sourcePort
      destinationPort:(uint16_t)destinationPort;
//       fragmentLength:(uint16_t)fragmentLength;

+ (NSData *)sctpChunk:(NSData *)payload
            chunkType:(uint8_t)type
                flags:(uint8_t)flags
                  tsn:(uint32_t)tsn
               stream:(uint16_t)stream
 streamSequenceNumber:(uint16_t)streamSequence
   protocolIdentifier:(uint32_t)pid;

+ (NSData *)sctpPacket:(NSArray<NSMutableData *>*)chunks
            sourcePort:(uint16_t)sourcePort
       destinationPort:(uint16_t)destinationPort
       verificationTag:(uint32_t)ver;

+ (uint16_t)  layer4_checksum:(NSData *)payload
                    headerPtr:(uint8_t *)headerPtr
                    headerLen:(int)headerLen
                     sourceIp:(NSString *)sourceIP
                destinationIp:(NSString *)destinationIP
                     protocol:(uint8_t)protocol
               fragmentLength:(uint16_t)fragmentLength;

@end
