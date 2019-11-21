//
//  PacketHandler.h
//  sniff-ss7
//
//  Created by Andreas Fink on 21.11.19.
//  Copyright © 2019 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulibpcap/ulibpcap.h>

@interface PacketHandler : NSObject<UMPCAPLiveTraceDelegateProtocol>
{
    NSString    *_syslogHost;
    int         _syslogPort;
}

@property(readwrite,strong,atomic)    NSString *syslogHost;
@property(readwrite,assign,atomic)    int       syslogPort;

@end

