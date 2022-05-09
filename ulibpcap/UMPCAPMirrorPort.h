//
//  UMPCAPMirrorPort.h
//  ulibpcap
//
//  Created by Andreas Fink on 09.05.22.
//  Copyright © 2022 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>

typedef enum UMPCAPMirrorPort_error
{
    UMPCAPMirrorPort_error_none                = 0,
    UMPCAPMirrorPort_can_not_open_socket       = 1,
    UMPCAPMirrorPort_can_not_find_interface    = 2,
    UMPCAPMirrorPort_can_not_find_mac_address  = 3,
} UMPCAPMirrorPort_error;


@interface UMPCAPMirrorPort : UMObject
{
    NSString *_name;
    NSString *_interfaceName;
    int     _interfaceIndex;
    int      _linkNumber;
    NSData   *_localMacAddress;
    NSData   *_remoteMacAddress;
    BOOL    _verbose;
    int     _sockfd;
}


- (UMPCAPMirrorPort_error)openDevice;
- (UMPCAPMirrorPort_error)openDevice:(NSString *)deviceName;

@end
