//
//  main.m
//  pcap-test
//
//  Created by Andreas Fink on 26.02.18.
//  Copyright © 2018 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "UMPCAPFile.h"
#import "UMPCAPPseudoConnection.h"

int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        UMPCAPPseudoConnection *con = [[UMPCAPPseudoConnection alloc]init];
        con.protocol = UMPCAPPseudoConnection_ip_protocol_tcp;
        con.localPort = 80;
        con.remotePort = 1000;

        UMPCAPPseudoConnection *con2 = [[UMPCAPPseudoConnection alloc]init];
        con2.protocol = UMPCAPPseudoConnection_ip_protocol_udp;
        con2.localPort = 514;
        con2.remotePort = 514;

        UMPCAPFile *pf = [[UMPCAPFile alloc]init];
        pf.filename = @"dup.cap";
        if([pf openForPseudoConnection])
        {
            system("pwd");
        }
        else
        {
            fprintf(stderr,"couldnt open file %s\n",argv[1]);
            exit(-1);
        }

        unsigned char ipPayload[] = { 0xc9,0x65,0x01,0xbb,0x01,0x89,0x81,0xf8,0x62,0xd9,0x34,0x66,0x80,0x18,0x10,0x00,0x18,0xd1,0x00,0x00,0x01,0x01,0x08,0x0a,0x0a,0x8b,0x92,0x38,0x62,0xbe,0x6a,0x7d };
        NSData *ipData = [NSData dataWithBytes:ipPayload length:sizeof(ipPayload)];
        [pf writePdu: [con ipv4Packet:ipData inbound:YES]];

        unsigned char tcpPayload[] = "GET / HTTP/1.0\nHost: hello.world.com\n\n";
        NSData *tcpData = [NSData dataWithBytes:tcpPayload length:sizeof(tcpPayload)];
        [pf writePdu: [con tcpPacket:tcpData inbound:YES]];

        unsigned char udpPayload[] = "some UDP payload\n\n";
        NSData *udpData = [NSData dataWithBytes:udpPayload length:sizeof(udpPayload)];
        [pf writePdu: [con2 udpPacket:udpData inbound:YES]];

        [pf close];
    }
    return 0;
}

