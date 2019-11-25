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
{
    NSLog(@"[%@] %@ -> [%@] %@: %@",pkt.source_ethernet_address,pkt.ip_src,pkt.destination_ethernet_address,pkt.ip_dst,pkt.data.hexString);


    if(pkt.ip_p == 132) /* SCTP */
    {
    }
}



- (void)processSCTP:(UMPCAPLiveTracePacket *)pkt
{
    NSLog(@"[%@] %@ -> [%@] %@: %@",pkt.source_ethernet_address,pkt.ip_src,pkt.destination_ethernet_address,pkt.ip_dst,pkt.data.hexString);
    uint8_t *bytes = pkt.data.bytes;
    
}


@end
