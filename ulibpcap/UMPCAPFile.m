//
//  UMPCAPFile.m
//  ulibpcap
//
//  Created by Andreas Fink on 25.05.16.
//  Copyright © 2016 Andreas Fink. All rights reserved.
//

#import "UMPCAPFile.h"

#include <pcap/pcap.h>

@implementation UMPCAPFile
@synthesize filename;

- (UMPCAPFile *)init
{
    self = [super init];
    if(self)
    {
        NSString *uuidStr = [UMUUID UUID];
        NSString *prefix = @"pcap";
        
        filename = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"%@-%@", prefix, uuidStr]];
    }
    return self;
}

- (BOOL)openForDLT:(int)dlt
{
    handle = pcap_open_dead(dlt, 1 << 16);
    if(handle==NULL)
    {
        return NO;
    }
    dumper = pcap_dump_open(handle, filename.UTF8String);
    if(dumper == NULL)
    {
        return NO;
    }
    return YES;
}

-(BOOL) openForSccp
{
    return [self openForDLT:DLT_SCCP];
}

-(BOOL) openForMtp3
{
    return [self openForDLT:DLT_MTP3];
}


- (void) close
{
    pcap_dump_close(dumper);
    pcap_close(handle);
    dumper=NULL;
    handle=NULL;
}

- (void)flush
{
    pcap_dump_flush(dumper);
}

- (void)writePdu:(NSData *)pdu
{
    if(dumper==NULL)
    {
        NSLog(@"trying to write to closed UMPCAPFile");
        return;
    }
    struct   pcap_pkthdr pcap_hdr;
    struct	timezone tzp;
    gettimeofday(&pcap_hdr.ts, &tzp);
    pcap_hdr.caplen = (bpf_u_int32)[pdu length];
    pcap_hdr.len = pcap_hdr.caplen;
    pcap_dump((u_char *)dumper, &pcap_hdr, [pdu bytes]);
}

- (NSData *)dataAndClose
{
    if(dumper)
    {
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
        pcap_close(handle);
        dumper=NULL;
        handle=NULL;
    }
    NSData *d = [NSData dataWithContentsOfFile:filename];
    return d;
}

@end
