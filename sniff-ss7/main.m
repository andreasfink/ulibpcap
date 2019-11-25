//
//  main.m
//  sniff-ss7
//
//  Created by Andreas Fink on 01.11.2019.
//  Copyright © 2019 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <Foundation/Foundation.h>
#import <ulibpcap/ulibpcap.h>
#ifdef __APPLE__
#import "/Library/Application Support/FinkTelecomServices/frameworks/uliblicense/uliblicense.h"
#else
#import <uliblicense/uliblicense.h>
#endif
#import "../version.h"
#import "PacketHandler.h"

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        NSDictionary *appDefinition = @
        {
            @"version" : @(VERSION),
            @"executable" : @"sniff-ss7",
            @"run-as" : @(argv[0]),
            @"copyright" : @"© 2019 Andreas Fink",
        };

        NSArray *commandLineDefinition = @[
                                           @{
                                               @"name"  : @"version",
                                               @"short" : @"-V",
                                               @"long"  : @"--version",
                                               @"help"  : @"shows the software version"
                                               },
                                           @{
                                               @"name"  : @"verbose",
                                               @"short" : @"-v",
                                               @"long"  : @"--verbose",
                                               @"help"  : @"enables verbose mode"
                                               },
                                           @{
                                               @"name"  : @"help",
                                               @"short" : @"-h",
                                               @"long"  : @"--help",
                                               @"help"  : @"shows the help screen",
                                               },
                                           @{
                                               @"name"  : @"device",
                                               @"short" : @"-d",
                                               @"long"  : @"--device",
                                               @"argument" : @"devicename",
                                               @"help"  : @"the device to sniff on",
                                           },
                                           @{
                                               @"name"  : @"file",
                                               @"short" : @"-F",
                                               @"long"  : @"--file",
                                               @"argument" : @"filename",
                                               @"help"  : @"the pcap file to read from",
                                           },
                                           @{
                                               @"name"  : @"filter",
                                               @"short" : @"-f",
                                               @"long"  : @"--filter",
                                               @"argument" : @"filter rule",
                                               @"help"  : @"the capture filter rule",
                                           },
                                           @{
                                               @"name"  : @"host",
                                               @"short" : @"-h",
                                               @"long"  : @"--host",
                                               @"argument" : @"destination host",
                                               @"help"  : @"destination host to where the syslog packets will be sent. defaults to localhost",
                                               },
                                            @{
                                               @"name"  : @"port",
                                               @"short" : @"-p",
                                               @"long"  : @"--port",
                                               @"help"  : @"UDP port where syslog packets are being sent. defaults to 514",
                                            }];

        UMCommandLine *_commandLine = [[UMCommandLine alloc]initWithCommandLineDefintion:commandLineDefinition
                                                                           appDefinition:appDefinition
                                                                                    argc:argc
                                                                                    argv:argv];

        [_commandLine handleStandardArguments];
        NSDictionary *params = _commandLine.params;
        PacketHandler *ph = [[PacketHandler alloc]init];
        ph.syslogHost = @"127.0.0.1";
        ph.syslogPort = 514;
        BOOL verbose=NO;
        NSString *capturingFilter = NULL;

        NSMutableArray<UMPCAPLiveTrace *> *traceSources = [[NSMutableArray alloc]init];
        if(params[@"verbose"])
        {
            verbose = YES;
        }

        NSArray *a = params[@"file"];
        if(a.count  > 0)
        {
            for(NSString *filename in a)
            {
                UMPCAPLiveTrace *trace = [[UMPCAPLiveTrace alloc]initWithName:filename];
                if(trace!=NULL)
                {
                    UMPCAP_LiveTraceError e = [trace openFile:filename];
                    if(e==UMPCAP_LiveTraceError_none)
                    {
                        [traceSources addObject:trace];
                    }
                }
            }
        }

        a = params[@"device"];
        if(a.count > 0)
        {
            for(NSString *device in a)
            {
                UMPCAPLiveTrace *trace = [[UMPCAPLiveTrace alloc]initWithName:device];
                if(trace!=NULL)
                {
                    UMPCAP_LiveTraceError e;
                    if([device isEqualToStringCaseInsensitive:@"default"])
                    {
                        e = [trace openDevice:NULL];
                    }
                    else
                    {
                        e = [trace openDevice:device];
                    }
                    if(e==UMPCAP_LiveTraceError_none)
                    {
                        [traceSources addObject:trace];
                    }
                }
            }
        }

        
        if(params[@"host"])
        {
            NSArray *a = params[@"host"];
            if(a.count >= 1)
            {
                ph.syslogHost = a[0];
            }
        }

        if(params[@"port"])
        {
            NSArray *a = params[@"port"];
            if(a.count >= 1)
            {
                ph.syslogPort = [a[0] intValue];
            }
        }

        if(params[@"filter"])
        {
            NSArray *a = params[@"filter"];
            if(a.count >= 1)
            {
                capturingFilter = a[0];
            }
        }

        if(traceSources.count==0)
        {
            fprintf(stderr,"Error: No trace sources have been given. exiting\n");
            exit(-1);
        }
        for(UMPCAPLiveTrace *traceSource in traceSources)
        {
            traceSource.delegate = ph;
            traceSource.capturingRule = capturingFilter;
            [traceSource start];
        }
        while(1)
        {
            int runningCount = 0;
            for(UMPCAPLiveTrace *traceSource in traceSources)
            {
                if(traceSource.isRunning)
                {
                    runningCount++;
                }
            }
            if(runningCount==0)
            {
                break;
            }
            sleep(1);
        }
    }
    return 0;
}

