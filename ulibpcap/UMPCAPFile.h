//
//  UMPCAPFile.h
//  ulibpcap
//
//  Created by Andreas Fink on 25.05.16.
//  Copyright © 2017 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>
#import <pcap/pcap.h>

@interface UMPCAPFile : UMObject
{
    NSString        *filename;
    pcap_t          *handle;
    pcap_dumper_t   *dumper;

}

@property(readwrite,strong)     NSString        *filename;

- (BOOL) openForDLT:(int)dlt; /* returns success */
- (BOOL) openForSccp; /* returns success */
- (BOOL) openForMtp3;
- (void) close;
- (void) flush;
- (void) writePdu:(NSData *)pdu;
- (NSData *)dataAndClose;

@end
