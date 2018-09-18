//
//  UMPCAPFile.h
//  ulibpcap
//
//  Created by Andreas Fink on 25.05.16.
//  Copyright © 2017 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>
#import <pcap/pcap.h>

typedef enum UMPCAP_Mode
{
    UMPCAP_Mode_Ethernet = 0,
    UMPCAP_Mode_PseudoConnection = 1,
    UMPCAP_Mode_SCCP = 2,
    UMPCAP_Mode_MTP3 = 3,
    UMPCAP_Mode_MTP2 = 4, /* includes pseudo header */
} UMPCAP_Mode;


@class UMPCAPPseudoConnection;

@interface UMPCAPFile : UMObject
{
    NSString        *filename;
    pcap_t          *handle;
    pcap_dumper_t   *dumper;
    UMPCAP_Mode     _mode;
}

@property(readwrite,strong)     NSString        *filename;
@property(readwrite,assign)     UMPCAP_Mode     mode;

- (BOOL) openForDLT:(int)dlt; /* returns success */
- (BOOL) openForSccp; /* returns success */
- (BOOL) openForMtp3;
- (BOOL) openForMtp2;
- (BOOL) openForEthernet;
- (BOOL) openForPseudoConnection;
- (void) close;
- (void) flush;
- (void) writePdu:(NSData *)pdu;
- (void) writePdu:(NSData *)pdu withPseudoHeader:(UMPCAPPseudoConnection *)con inbound:(BOOL)inbound;
- (void)writeItuMtp3Pdu:(NSData *)pdu
              timestamp:(struct timeval *)timestamp
                     si:(int)si
                     ni:(int)ni
                    sls:(int)sls
                    opc:(int)opc
                    dpc:(int)dpc;

- (NSData *)dataAndClose;

@end
