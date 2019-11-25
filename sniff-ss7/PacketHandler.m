//
//  PacketHandler.m
//  sniff-ss7
//
//  Created by Andreas Fink on 21.11.19.
//  Copyright © 2019 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import "PacketHandler.h"
#include <netinet/ip.h>

@implementation PacketHandler

- (void)handlePacket:(UMPCAPLiveTracePacket *)pkt
{/*
    NSMutableString *s = [[NSMutableString alloc]init];
    [s appendFormat:@" Timestamp: %@\n",pkt.timestamp];
    [s appendFormat:@" Captured Data Size: %u\n",pkt.caplen];
    [s appendFormat:@" Packet Data Size: %u\n",pkt.len];
    [s appendFormat:@" Comment: %@\n",pkt.comment];
    [s appendFormat:@" Data: %@\n",pkt.data.hexString];
    NSLog(@"Got packet: \n%@",s);*/
    NSLog(@"[%@] %@ -> [%@] %@: %@",pkt.source_ethernet_address,pkt.ip_src,pkt.destination_ethernet_address,pkt.ip_dst,pkt.data.hexString);

    if(pkt.ip_version==4)
    {
        [self processIPv4:pkt];
    }
    else if(pkt.ip_version==6)
    {
        [self processIPv6:pkt];
    }
}



- (void)processIPv4:(UMPCAPLiveTracePacket *)pkt
{

/* IP header  https://tools.ietf.org/html/rfc791

  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |Version|  IHL  |Type of Service|          Total Length         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |         Identification        |Flags|      Fragment Offset    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |  Time to Live |    Protocol   |         Header Checksum       |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                       Source Address                          |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Destination Address                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                    Options                    |    Padding    |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */
}

- (void)processIPv6:(UMPCAPLiveTracePacket *)pkt
{
}

@end
