//
//  UMPCAPFile.m
//  ulibpcap
//
//  Created by Andreas Fink on 25.05.16.
//  Copyright © 2017 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import "UMPCAPFile.h"
#import "UMPCAPPseudoConnection.h"

#include <pcap/pcap.h>
struct pcap_pkthdr *hdr;

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
    _mode = UMPCAP_Mode_SCCP;
    return [self openForDLT:DLT_SCCP];
}

-(BOOL) openForMtp3
{
    _mode = UMPCAP_Mode_MTP3;
    return [self openForDLT:DLT_MTP3];
}

-(BOOL) openForMtp2
{
    _mode = UMPCAP_Mode_MTP2;
    return [self openForDLT:DLT_MTP2_WITH_PHDR];
}


-(BOOL) openForPseudoConnection
{
 
    _mode = UMPCAP_Mode_PseudoConnection;
    return [self openForDLT:DLT_EN10MB];
}

-(BOOL) openForEthernet
{
    
    _mode = UMPCAP_Mode_Ethernet;
    return [self openForDLT:DLT_EN10MB];
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


/* Packet "pseudo-header" for MTP2 files. */



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

- (void)writePdu:(NSData *)pdu withPseudoHeader:(UMPCAPPseudoConnection *)con inbound:(BOOL)inbound
{
    if(dumper==NULL)
    {
        NSLog(@"trying to write to closed UMPCAPFile");
        return;
    }
    struct   pcap_pkthdr pcap_hdr;
    struct    timezone tzp;
    gettimeofday(&pcap_hdr.ts, &tzp);
    
    switch(_mode)
    {
        case UMPCAP_Mode_PseudoConnection:
        {
            switch (con.protocol)
            {
                case UMPCAPPseudoConnection_ip_protocol_tcp:
                    pdu = [con tcpPacket:pdu inbound:inbound];
                    break;
                case UMPCAPPseudoConnection_ip_protocol_udp:
                    pdu = [con udpPacket:pdu inbound:inbound];
                    break;
                default:
                    pdu = [con ipv4Packet:pdu inbound:inbound];
                    break;
            }
            break;
        }
        case UMPCAP_Mode_Ethernet:
            pdu = [con ethernetPacket:pdu inbound:inbound];
            break;
        default:
            break;
    }
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
