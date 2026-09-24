//
//  UMPCAPLiveTraceDelegate.h
//  ulibpcap
//
//  Created by Andreas Fink on 21.11.19.
//  Copyright © 2019 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>


@class UMPCAPLiveTracePacket;

@protocol  UMPCAPLiveTraceDelegateProtocol<NSObject>

- (void)handleEthernetPacket:(UMPCAPLiveTracePacket *)pkt;
- (void)handleMtp3Packet:(UMPCAPLiveTracePacket *)pkt;

@end

