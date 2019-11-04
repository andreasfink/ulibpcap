//
//  UMPCAPLiveTrace.m
//  ulibpcap
//
//  Created by Andreas Fink on 01.11.2019.
//  Copyright © 2019 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import "UMPCAPLiveTrace.h"
#import "UMPCAPLiveTracePacket.h"
#import <CoreFoundation/CoreFoundation.h>

static void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

@implementation UMPCAPLiveTrace

- (UMPCAPLiveTrace *)init
{
    return [self initWithName:@"UMPCAPLiveTrace"];
}

- (UMPCAPLiveTrace *)initWithName:(NSString *)name
{
    self =[super initWithName:name workSleeper:NULL];
    if(self)
    {
        UMPCAP_LiveTraceError e = [self genericInitialisation];
        if((e != UMPCAP_LiveTraceError_can_not_find_default_device) && (e!=UMPCAP_LiveTraceError_none))
        {
            NSLog(@"%@",_lastError);
            return NULL;
        }
        if(e==UMPCAP_LiveTraceError_can_not_find_default_device)
        {
            NSLog(@"%@",_lastError);
        }
        _lock =[[UMMutex alloc]init];
    }
    return self;
}

- (UMPCAP_LiveTraceError)genericInitialisation
{
    _snaplen = BUFSIZ;
    _promisc = 1;
    _to_ms = 1000;

    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = pcap_lookupdev(errbuf);
    if(dev)
    {
        _defaultDevice = @(dev);
    }
    else
    {
        _lastError = [NSString stringWithFormat:@"Couldn't find default device: %s\n",
            errbuf];
        return UMPCAP_LiveTraceError_can_not_find_default_device;
    }
    return UMPCAP_LiveTraceError_none;
}

- (UMPCAP_LiveTraceError)openDevice
{
    [_lock lock];
    @try
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        _handle = pcap_open_live(_deviceName.UTF8String, _snaplen,_promisc, _to_ms,errbuf);
        if (_handle == NULL)
        {
            _lastError = [NSString stringWithFormat:@"Couldn't open device %@: %s", _deviceName, errbuf];
            return  UMPCAP_LiveTraceError_can_not_open;
        }
        
        if (pcap_datalink(_handle) != DLT_EN10MB)
        {
            _lastError = [NSString stringWithFormat:@"Device %@ doesn't provide Ethernet headers - not supported", _deviceName];
            return UMPCAP_LiveTraceError_unsupported_datalink_type;
        }

        bpf_u_int32 netmask = 0;
        memset(&_fp,0,sizeof(_fp));
        if(pcap_compile(_handle, &_fp, _capturingRule.UTF8String, 1,netmask) == -1)
        {
            _lastError = [NSString stringWithFormat:@"Can not compile capture rule %@ ", _capturingRule];
            return UMPCAP_LiveTraceError_unsupported_capturing_rule;
        }
        if(pcap_setfilter(_handle, &_fp) ==-1)
        {
            _lastError = [NSString stringWithFormat:@"Can not install capture filter %@ ", _capturingRule];
            return UMPCAP_LiveTraceError_unsupported_capturing_rule;
        }
        _isOpen = YES;
    }
    @catch (NSException *e)
    {
        NSLog(@"Exception %@",e);
    }
    @finally
    {
            [_lock unlock];
    }
}

- (UMPCAP_LiveTraceError)closeDevice
{
    if(_isOpen)
    {
        pcap_close(_handle);
        _isOpen = NO;
    }
    [_lock unlock];
    return UMPCAP_LiveTraceError_none;
}

+ (NSString *)dataLinkTypeToString:(int)dl
{
    switch(dl)
    {
        case DLT_NULL:
            return @"NULL";
        case DLT_EN10MB:
            return @"EN10MB";
        case DLT_EN3MB:
            return @"EN3MB";
        case DLT_AX25:
            return @"AX25";
        case DLT_PRONET:
            return @"PRONET";
        case DLT_CHAOS:
            return @"CHAOS";
        case DLT_IEEE802:
            return @"IEEE802";
        case DLT_ARCNET:
            return @"ARCNET";
        case DLT_SLIP:
            return @"SLIP";
        case DLT_PPP:
            return @"PPP";
        case DLT_FDDI:
            return @"FDDI";
        case DLT_SCCP:
            return @"SCCP";
        case DLT_MTP3:
            return @"MTP3";
        case DLT_MTP2:
            return @"MTP2";
        case DLT_MTP2_WITH_PHDR:
            return @"MTP2_WITH_PHDR";
        default:
            return @"UNKNOWN";
    }
}


- (UMPCAP_LiveTraceError)start
{
    if(_isRunning)
    {
        return UMPCAP_LiveTraceError_none;
    }
    UMPCAP_LiveTraceError e = UMPCAP_LiveTraceError_none;
    [_lock lock];
    @try
    {
        if(_isOpen==NO)
        {
            e = [self openDevice];
            if(e!=UMPCAP_LiveTraceError_none)
            {
                return e;
            }
        }
        _isRunning = YES;
        [self startBackgroundTask];
    }
    @catch(NSException *ex)
    {
        NSLog(@"%@",ex);
    }
    @finally
    {
        [_lock unlock];
    }
    return e;
}


- (UMPCAP_LiveTraceError)stop
{
    UMPCAP_LiveTraceError e = UMPCAP_LiveTraceError_none;
    [_lock lock];
    @try
    {
        if(_isRunning == YES)
        {
            [self shutdownBackgroundTask];
            _isRunning = NO;
        }
        if(_isOpen==NO)
        {
            [self closeDevice];
        }
    }
    @catch(NSException *ex)
    {
        NSLog(@"%@",ex);
    }
    @finally
    {
        [_lock unlock];
    }
    return e;
}

- (int)work /* should return positive value for work items done, 0 for no work done  and -1 for termination */
{
    _itemsReceived = [[NSMutableArray alloc]init];
    
    int cnt = 1;
    u_char *arg = (u_char *)(__bridge CFTypeRef)self;
    pcap_loop(_handle, cnt, got_packet, arg);

    return 0;
}


@end

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);

void got_packet(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet)
{
    UMPCAPLiveTrace *obj = (__bridge UMPCAPLiveTrace *)(CFTypeRef)args;
    
    struct pcap_pkthdr {
        struct timeval ts;    /* time stamp */
        bpf_u_int32 caplen;    /* length of portion present */
        bpf_u_int32 len;    /* length this packet (off wire) */
    #ifdef __APPLE__
        char comment[256];
    #endif
    };
    
    NSTimeInterval t = header->ts.tv_sec + (header->ts.tv_usec/1000000.0);
    UMPCAPLiveTracePacket *pkt = [[UMPCAPLiveTracePacket alloc]init];
    pkt.timestamp = [[NSDate alloc]initWithTimeIntervalSinceReferenceDate:t];
    pkt.caplen = header->caplen;
    pkt.len = header->len;
}
