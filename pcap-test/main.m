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
        uint8_t data[] = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x0A };
        
        uint8_t srcMac[] = { 0x70,     0xB3,     0xD5,     0x23,     0xB0,     0x00,};
        uint8_t dstMac[] = { 0x70,     0xB3,    0xD5,     0x23,     0xB0,     0x06, };

        NSData *tcpPayload = [NSData dataWithBytes:data length:sizeof(data)];
        NSData *srcMacAddr = [NSData dataWithBytes:srcMac length:sizeof(srcMac)];
        NSData *dstMacAddr = [NSData dataWithBytes:dstMac length:sizeof(dstMac)];



        NSData *sctpDataChunk = [UMPCAPMirrorPort sctpChunk:tcpPayload
                                                      flags:0
                                                        tsn:999
                                                     stream:1
                                       streamSequenceNumber:222
                                          protocolIdentifier:5];
        NSArray *a = @[sctpDataChunk];
        
        NSData *sctpData = [UMPCAPMirrorPort sctpPacket:a
                                             sourcePort:2000
                                        destinationPort:2001
                                        verificationTag:99199];

        NSData *udpData = [UMPCAPMirrorPort udpPacket:tcpPayload
                                        sourceAddress:@"10.10.10.10"
                                   destinationAddress:@"20.20.20.20"
                                            sourcePort:199
                                       destinationPort:199];
        
        NSData *tcpData = [UMPCAPMirrorPort tcpPacket:tcpPayload
                                        sourceAddress:@"10.10.10.10"
                                   destinationAddress:@"20.20.20.20"
                                            sourcePort:65000
                                       destinationPort:23
                                        sequenceNumber:123
                                             ackNumber:321
                                                 flags:0
                                            windowSize:512
                                         urgentPointer:0
                                        fragmentLength:0];

        NSData *ipData1 = [UMPCAPMirrorPort ipv4Packet:tcpData
                                                 dscp:0
                                                flags:0
                                                  ttl:32
                                             protocol:6 /* TCP */
                                        sourceAddress:@"10.10.10.10"
                                   destinationAddress:@"20.20.20.20"
                                               ident:0
                                            fragment:0];

        NSData *ipData2 = [UMPCAPMirrorPort ipv4Packet:udpData
                                                 dscp:0
                                                flags:0
                                                  ttl:32
                                             protocol:17 /* UDP */
                                        sourceAddress:@"10.10.10.10"
                                   destinationAddress:@"20.20.20.20"
                                               ident:0
                                            fragment:0];

        NSData *ipData3 = [UMPCAPMirrorPort ipv4Packet:sctpData
                                                 dscp:0
                                                flags:0
                                                  ttl:32
                                             protocol:132 /* SCTP */
                                        sourceAddress:@"10.10.10.10"
                                   destinationAddress:@"20.20.20.20"
                                               ident:0
                                            fragment:0];


        NSData *ethernetData1 = [UMPCAPMirrorPort ethernetPacket:ipData1
                                               sourceMacAddress:srcMacAddr
                                          destinationMacAddress:dstMacAddr
                                                   ethernetType:0x0800];

        NSData *ethernetData2 = [UMPCAPMirrorPort ethernetPacket:ipData2
                                               sourceMacAddress:srcMacAddr
                                          destinationMacAddress:dstMacAddr
                                                   ethernetType:0x0800];

        NSData *ethernetData3 = [UMPCAPMirrorPort ethernetPacket:ipData3
                                               sourceMacAddress:srcMacAddr
                                          destinationMacAddress:dstMacAddr
                                                   ethernetType:0x0800];

        NSLog(@"Sending data1: %@",ethernetData1.hexString);
        NSLog(@"Sending data2: %@",ethernetData2.hexString);
        NSLog(@"Sending data3: %@",ethernetData3.hexString);
        UMPCAPMirrorPort *con = [[UMPCAPMirrorPort alloc]init];
        NSLog(@"con: %@",con);
        int i = [con openDevice:@"en0"];
        NSLog(@"openDevice(en0): %d %@",i,con.lastError);

        i = [con writeEthernetPacket:ethernetData1];
        NSLog(@"writeEthernetPacket: %d %@",i,con.lastError);
        i = [con writeEthernetPacket:ethernetData2];
        NSLog(@"writeEthernetPacket: %d %@",i,con.lastError);
        i = [con writeEthernetPacket:ethernetData3];
        NSLog(@"writeEthernetPacket: %d %@",i,con.lastError);

        
        
        [con close];
    }
    return 0;
}

