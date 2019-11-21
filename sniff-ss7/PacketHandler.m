//
//  PacketHandler.m
//  sniff-ss7
//
//  Created by Andreas Fink on 21.11.19.
//  Copyright © 2019 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import "PacketHandler.h"

@implementation PacketHandler

- (void)handlePacket:(UMPCAPLiveTracePacket *)pkt
{
    NSMutableString *s = [[NSMutableString alloc]init];
    [s appendFormat:@" Timestamp: %@\n",pkt.timestamp];
    [s appendFormat:@" Captured Data Size: %u\n",pkt.caplen];
    [s appendFormat:@" Packet Data Size: %u\n",pkt.len];
    [s appendFormat:@" Comment: %@\n",pkt.comment];
    [s appendFormat:@" Data: %@\n",pkt.data.hexString];
    NSLog(@"Got packet: \n%@",s);
}

@end
