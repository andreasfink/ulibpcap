//
//  UMPCAPLiveTracePacket.h
//  ulibpcap
//
//  Created by Andreas Fink on 01.11.2019.
//  Copyright © 2019 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>
#import <pcap/pcap.h>

@interface UMPCAPLiveTracePacket : UMObject
{
    NSDate          *_timestamp;    /* time stamp */
    bpf_u_int32     _caplen;    /* length of portion present */
    bpf_u_int32     _len;    /* length this packet (off wire) */
    NSString        *_comment;
    NSData          *_data;
}

@property(readwrite,atomic,strong)  NSDate         *timestamp;
@property(readwrite,atomic,assign)  bpf_u_int32    caplen;
@property(readwrite,atomic,assign) bpf_u_int32     len;
@property(readwrite,atomic,strong) NSString        *comment;
@property(readwrite,atomic,strong) NSData          *data;

@end
