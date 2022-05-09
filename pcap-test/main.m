//
//  main.m
//  pcap-test
//
//  Created by Andreas Fink on 26.02.18.
//  Copyright © 2018 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "UMPCAPFile.h"
#import "UMPCAPMirrorPort.h"

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        
        UMPCAPMirrorPort *con = [[UMPCAPMirrorPort alloc]init];
        [con openDevice:@"en0"];
        
        
        unsigned char ipPayload[] = { 0xc9,0x65,0x01,0xbb,0x01,0x89,0x81,0xf8,0x62,0xd9,0x34,0x66,0x80,0x18,0x10,0x00,0x18,0xd1,0x00,0x00,0x01,0x01,0x08,0x0a,0x0a,0x8b,0x92,0x38,0x62,0xbe,0x6a,0x7d };
        NSData *ipData = [NSData dataWithBytes:ipPayload length:sizeof(ipPayload)];
        
    }
    return 0;
}

