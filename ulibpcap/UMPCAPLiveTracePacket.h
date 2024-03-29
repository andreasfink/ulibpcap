//
//  UMPCAPLiveTracePacket.h
//  ulibpcap
//
//  Created by Andreas Fink on 01.11.2019.
//  Copyright © 2019 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>
#import <pcap/pcap.h>

typedef enum  UMPCAPLiveTracePacketDirection
{
    UMPCAPLiveTracePacketDirection_Unknown = 0,
    UMPCAPLiveTracePacketDirection_ATOB = 1,
    UMPCAPLiveTracePacketDirection_BTOA = 2,
} UMPCAPLiveTracePacketDirection;

@interface UMPCAPLiveTracePacket : UMObject
{
    NSDate                          *_timestamp;    /* time stamp */
    bpf_u_int32                     _caplen;    /* length of portion present */
    bpf_u_int32                     _len;    /* length this packet (off wire) */
    NSString                        *_comment;
    int                             _pcp;
    int                             _dei;
    int                             _vlan;
    int                             _pcp_qinq;
    int                             _dei_qinq;
    int                             _vlan_qinq;
    int                             _frameType;
    int                             _eth_packet_type;
    int                             _ip_version;
    NSString                        *_source_ethernet_address;
    NSString                        *_destination_ethernet_address;
    NSData                          *_data;
    u_char                          _ip_tos;                 /* type of service */
    u_short                         _ip_len;                 /* total length */
    u_short                         _ip_id;                  /* identification */
    u_short                         _ip_off;                 /* fragment offset field */
    u_char                          _ip_ttl;                 /* time to live */
    u_char                          _ip_p;                   /* protocol */
    u_short                         _ip_sum;                 /* checksum */
    NSString                        *_ip_src;
    NSString                        *_ip_dst;
    int                             _source_port;
    int                             _destination_port;
    UMPCAPLiveTracePacketDirection  _direction;
}

@property(readwrite,atomic,strong)  NSDate         *timestamp;
@property(readwrite,atomic,assign)  bpf_u_int32    caplen;
@property(readwrite,atomic,assign) bpf_u_int32     len;
@property(readwrite,atomic,strong) NSString        *comment;
@property(readwrite,atomic,assign) int             pcp;
@property(readwrite,atomic,assign) int             dei;
@property(readwrite,atomic,assign) int             vlan;
@property(readwrite,atomic,assign) int             pcp_qinq;
@property(readwrite,atomic,assign) int             dei_qinq;
@property(readwrite,atomic,assign) int             vlan_qinq;
@property(readwrite,atomic,assign) int             frameType;
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
@property(readwrite,atomic,assign) int             source_port;
@property(readwrite,atomic,assign) int             destination_port;
@property(readwrite,atomic,assign) UMPCAPLiveTracePacketDirection             direction;

@end
