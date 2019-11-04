//
//  UMPCAPLiveTrace.h
//  ulibpcap
//
//  Created by Andreas Fink on 01.11.2019.
//  Copyright © 2019 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <ulib/ulib.h>
#import <pcap/pcap.h>


typedef enum UMPCAP_LiveTraceError
{
    UMPCAP_LiveTraceError_none = 0,
    UMPCAP_LiveTraceError_can_not_find_default_device = 1,
    UMPCAP_LiveTraceError_can_not_open = 2,
    UMPCAP_LiveTraceError_unsupported_datalink_type = 3,
    UMPCAP_LiveTraceError_unsupported_capturing_rule = 4,

} UMPCAP_LiveTraceError;


@interface UMPCAPLiveTrace : UMBackgrounder
{
    NSString        *_defaultDevice;
    NSString        *_deviceName;
    pcap_t          *_handle;
    int             _snaplen;
    int             _promisc;
    int             _to_ms;
    NSString        *_lastError;
    NSString        *_capturingRule;
    struct bpf_program _fp;
    UMMutex         *_lock;
    BOOL            _isOpen;
    BOOL            _isRunning;
    
    NSMutableArray  *_itemsReceived;
}

@property(readwrite,strong,atomic)  NSString *deviceName;
@property(readwrite,strong,atomic)  NSString *capturingRule;
@property(readonly,strong,atomic)   NSString *lastError;

- (UMPCAPLiveTrace *)initWithName:(NSString *)name;

- (UMPCAP_LiveTraceError)openDevice;
- (UMPCAP_LiveTraceError)closeDevice;
- (UMPCAP_LiveTraceError)start;
- (UMPCAP_LiveTraceError)stop;

+ (NSString *)dataLinkTypeToString:(int)dl;
@end

