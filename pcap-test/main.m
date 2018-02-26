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
        
        char *b = "GET / HTTP/1.0\nHost: hello.world.com\n\n";
        NSData *d = [NSData dataWithBytes:b length:sizeof(b)];
        
        NSData *pdu = [con tcpPacket:d inbound:YES];
        [pf writePdu:pdu];
        [pf close];
    }
    return 0;
}

