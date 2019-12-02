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
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h>


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
        _lock =[[UMMutex alloc]initWithName:@"UMPCAPLiveTrace_mutex"];
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

- (UMPCAP_LiveTraceError)openDevice:(NSString *)deviceName
{
    UMPCAP_LiveTraceError err = UMPCAP_LiveTraceError_none;
    [_lock lock];
    if(deviceName==NULL)
    {
        _deviceName = _defaultDevice;
    }
    else
    {
        _deviceName = deviceName;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    if(_verbose)
    {
        NSLog(@"opening device %@ ",_deviceName);
    }
    _handle = pcap_open_live(_deviceName.UTF8String, _snaplen,_promisc, _to_ms,errbuf);
    if (_handle == NULL)
    {
        _lastError = [NSString stringWithFormat:@"Couldn't open device %@: %s", _deviceName, errbuf];
        if(_verbose)
        {
            NSLog(@"Error: %@ ",_lastError);
        }
        err =  UMPCAP_LiveTraceError_can_not_open;
    }

    else if (pcap_datalink(_handle) != DLT_EN10MB)
    {
        _lastError = [NSString stringWithFormat:@"Device %@ doesn't provide Ethernet headers - not supported", _deviceName];
        if(_verbose)
        {
            NSLog(@"Error: %@ ",_lastError);
        }
        err = UMPCAP_LiveTraceError_unsupported_datalink_type;
    }
    else
    {
        bpf_u_int32 netmask = 0;
        memset(&_fp,0,sizeof(_fp));
        if(pcap_compile(_handle, &_fp, _capturingRule.UTF8String, 1,netmask) != 0)
        {
            _lastError = [NSString stringWithFormat:@"Can not compile capture rule %@:\n%s", _capturingRule,pcap_geterr(_handle)];
            if(_verbose)
            {
                NSLog(@"Error: %@ ",_lastError);
            }
            err = UMPCAP_LiveTraceError_unsupported_capturing_rule;
        }
        else if(pcap_setfilter(_handle, &_fp) !=0)
        {
            _lastError = [NSString stringWithFormat:@"Can not install capture filter %@:\n%s", _capturingRule,pcap_geterr(_handle)];
            if(_verbose)
            {
                NSLog(@"Error: %@ ",_lastError);
            }
            err = UMPCAP_LiveTraceError_unsupported_capturing_rule;
        }
        else
        {
            _isOpen = YES;
            if(_verbose)
            {
                NSLog(@"device successfully opened");
            }
        }
    }
    [_lock unlock];
    return err;
}

- (UMPCAP_LiveTraceError)openFile:(NSString *)filename;
{
    UMPCAP_LiveTraceError err = UMPCAP_LiveTraceError_none;

    [_lock lock];
    _fileName = filename;
    _readingFromFile = YES;

    char errbuf[PCAP_ERRBUF_SIZE] ;
    memset(errbuf,0x00,PCAP_ERRBUF_SIZE);

    FILE *f = fopen(_fileName.UTF8String,"r+");
    if(f == NULL)
    {
        err = UMPCAP_LiveTraceError_can_not_open;
    }
    else
    {
        _handle = pcap_fopen_offline(f,errbuf);
        if(_handle == NULL)
        {
            NSLog(@"pcap_fopen_offline returns error %s",errbuf);
            err =  UMPCAP_LiveTraceError_can_not_open;
        }
        else
        {
            _isOpen = YES;
        }
    }
    [_lock unlock];
    return err;
}

- (UMPCAP_LiveTraceError)close
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
            return UMPCAP_LiveTraceError_not_open;
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
            [self close];
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
    
    u_char *arg = (u_char *)(__bridge CFTypeRef)self;
    int cnt = pcap_dispatch(_handle, 1000, got_packet, arg);
    if((cnt==0) && (_readingFromFile==YES))
    {
        _isRunning = NO;
        return -1;
    }
    return cnt;
}


@end

typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *, const u_char *);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    @autoreleasepool
    {
        UMPCAPLiveTrace *obj = (__bridge UMPCAPLiveTrace *)(CFTypeRef)args;
        NSTimeInterval t = header->ts.tv_sec + (header->ts.tv_usec/1000000.0);

        UMPCAPLiveTracePacket *pkt = [[UMPCAPLiveTracePacket alloc]init];
        pkt.timestamp = [NSDate dateWithTimeIntervalSince1970:t];

        /* lets start with the ether header... */
        struct ether_header *eptr = (struct ether_header *) packet;

        pkt.eth_packet_type = ntohs (eptr->ether_type);
        NSString *s = @"";
        int version=0;
        if(obj.verbose)
        {
            switch(pkt.eth_packet_type)
            {
                case ETHERTYPE_PUP:
                    s = @" PUP";
                    break;
                case ETHERTYPE_IP :
                    s = @" IP";
                    version=4;
                    break;
                case ETHERTYPE_ARP:
                    s = @" ARP";
                    break;
                case ETHERTYPE_REVARP:
                    s = @" REVARP";
                    break;
                case ETHERTYPE_VLAN:
                    s = @" VLAN";
                    break;
                case ETHERTYPE_IPV6:
                    s = @" IPV6";
                    version=6;
                    break;
    #ifdef ETHERTYPE_PAE
                case ETHERTYPE_PAE:
                    s = @" PAE";
                    break;
    #endif
    #ifdef ETHERTYPE_RSN_PREAUTH
                case ETHERTYPE_RSN_PREAUTH:
                    s = @" RSN_PREAUTH";
                    break;
    #endif
    #ifdef ETHERTYPE_PTP
                case ETHERTYPE_PTP:
                    s = @" PTP";
                    break;
    #endif
                case ETHERTYPE_LOOPBACK:
                    s = @" LOOPBACK";
                    break;
    #ifdef ETHERTYPE_IEEE802154
                case ETHERTYPE_IEEE802154:
                    s=@" IEEE802154";
                    break;
    #endif
                default:
                    s=@"";
            }
            NSLog(@"Ethertype: 0x%04x%@",pkt.eth_packet_type,s);
        }
        else
        {
            switch(pkt.eth_packet_type)
            {
                case ETHERTYPE_IP :
                    version=4;
                    break;
                case ETHERTYPE_IPV6:
                    version=6;
                    break;
            }
        }
        if(version==0)
        {
            return;
        }
        pkt.caplen      = header->caplen;
        pkt.len         = header->len;
    #ifdef __APPLE__
        pkt.comment     = @(header->comment);
    #endif

        uint8_t *ptr = eptr->ether_dhost;
        pkt.source_ethernet_address = [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]];
        ptr = eptr->ether_shost;
        pkt.destination_ethernet_address = [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x",ptr[0],ptr[1],ptr[2],ptr[3],ptr[4],ptr[5]];

        uint8_t *ip_ptr = (void *)eptr + sizeof(struct ether_header);

        if(header->caplen-sizeof(struct ether_header) > sizeof(struct ip))
        {
            const struct ip *ip_pkt = (const struct ip *)ip_ptr;
            pkt.ip_version = ip_pkt->ip_v;
            if(ip_pkt->ip_v == 4)
            {
                pkt.data            = [NSData dataWithBytes:(void *)packet + sizeof(struct ether_header)+ sizeof(struct ip) length:header->caplen-sizeof(struct ether_header) - sizeof(struct ip)];

                pkt.ip_tos  = ip_pkt->ip_tos;
                pkt.ip_len  = ip_pkt->ip_len;
                pkt.ip_id   = ip_pkt->ip_id;
                pkt.ip_off  = ip_pkt->ip_off;
                pkt.ip_ttl  = ip_pkt->ip_ttl;
                pkt.ip_p  = ip_pkt->ip_p;
                pkt.ip_sum  = ip_pkt->ip_sum;
                uint8_t *p = (uint8_t *)&ip_pkt->ip_src;
                pkt.ip_src = [NSString stringWithFormat:@"%d.%d.%d.%d",p[0],p[1],p[2],p[3]];
                p = (uint8_t *) &ip_pkt->ip_dst;
                pkt.ip_dst = [NSString stringWithFormat:@"%d.%d.%d.%d",p[0],p[1],p[2],p[3]];
                [obj.delegate handlePacket:pkt];
            }
        }
    }
}
