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
    int             _eth_packet_type;
    int             _ip_version;
    NSString        *_source_ethernet_address;
    NSString        *_destination_ethernet_address;
    NSData          *_data;


    u_char  _ip_tos;                 /* type of service */
    u_short _ip_len;                 /* total length */
    u_short _ip_id;                  /* identification */
    u_short _ip_off;                 /* fragment offset field */
    u_char  _ip_ttl;                 /* time to live */
    u_char  _ip_p;                   /* protocol */
    u_short _ip_sum;                 /* checksum */
    NSString *_ip_src;
    NSString *_ip_dst;

}

@property(readwrite,atomic,strong)  NSDate         *timestamp;
@property(readwrite,atomic,assign)  bpf_u_int32    caplen;
@property(readwrite,atomic,assign) bpf_u_int32     len;
@property(readwrite,atomic,strong) NSString        *comment;
@property(readwrite,atomic,strong) NSData          *data;
@property(readwrite,atomic,strong) NSString        *source_ethernet_address;
@property(readwrite,atomic,strong) NSString        *destination_ethernet_address;
@property(readwrite,atomic,assign) int             eth_packet_type;
@property(readwrite,atomic,assign) int             ip_version;
@property(readwrite,atomic,assign) u_char  ip_tos;                 /* type of service */
@property(readwrite,atomic,assign) u_short ip_len;                 /* total length */
@property(readwrite,atomic,assign) u_short ip_id;                  /* identification */
@property(readwrite,atomic,assign) u_short ip_off;                 /* fragment offset field */
@property(readwrite,atomic,assign) u_char ip_ttl;                  /* time to live */
@property(readwrite,atomic,assign) u_char  ip_p;                   /* protocol */
@property(readwrite,atomic,assign) u_short ip_sum;                 /* checksum */
@property(readwrite,atomic,strong) NSString *ip_src;
@property(readwrite,atomic,strong) NSString *ip_dst;


@end
