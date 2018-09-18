//
//  main.m
//  dump-huawei
//
//  Created by Andreas Fink on 18.09.2018.
//  Copyright © 2017 Andreas Fink (andreas@fink.org). All rights reserved.
//

#import <Foundation/Foundation.h>
#import "UMPCAPFile.h"


int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        if(argc < 3)
        {
            fprintf(stderr,"Usage: dump-huawei output.pcap  input.txt\n");
            exit(-1);
        }
        UMPCAPFile *pf = [[UMPCAPFile alloc]init];

        NSString *outputFileName = @(argv[1]);
        NSString *inputFileName = @(argv[2]);
        pf.filename = outputFileName;
        if([pf openForMtp3])
        {

        }
        else
        {
            fprintf(stderr,"couldnt open file %s\n",outputFileName.UTF8String);
            exit(-1);
        }
        NSError *err = NULL;
        NSString *allLines = [NSString stringWithContentsOfFile:inputFileName encoding:NSUTF8StringEncoding error:&err];
        if(err)
        {
            NSLog(@"%@",err);
        }
        if(allLines==NULL)
        {
            fprintf(stderr,"couldnt open file %s\n",inputFileName.UTF8String);
            exit(-1);
        }
        NSArray *lines = [allLines componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        if(lines.count ==0)
        {
            fprintf(stderr,"couldnt read file %s\n",inputFileName.UTF8String);
            exit(-1);
        }

        NSString *no=@"";
        NSString *timestamp=@"";
        int sio=0;
        int ni=0;
        int sls_slc=0;
        int opc=0;
        int dpc=0;
        NSData *pdu=NULL;
        BOOL write = NO;

        for(NSString *line in lines)
        {
            if([line hasPrefix:@"===="])
            {
                no=@"";
                timestamp=@"";
                sio=0;
                ni=0;
                sls_slc=0;
                opc=0;
                dpc=0;
                pdu=NULL;
                write = NO;
            }

            if([line hasPrefix:@"["])
            {
                NSArray *parts = [line componentsSeparatedByString:@"]"];
                if(parts.count==2)
                {
                    NSString *firstPart = [[parts[0] substringFromIndex:1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    NSString *secondPart = [parts[1] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
                    if([firstPart isEqualToString:@"No."])
                    {
                        no = secondPart;
                    }
                    else if([firstPart isEqualToString:@"TimeStamp"])
                    {
                        timestamp = secondPart;
                    }
                    else if([firstPart isEqualToString:@"Direction"])
                    {
                        //direction = secondPart;
                    }
                    else if([firstPart isEqualToString:@"SIO"])
                    {
                        if([secondPart isEqualToStringCaseInsensitive:@"sccp"])
                        {
                            sio=3;
                        }
                   }
                    else if([firstPart isEqualToString:@"NI"])
                    {
                        if((  [secondPart isEqualToStringCaseInsensitive:@"international"])
                           || ([secondPart isEqualToStringCaseInsensitive:@"int"])
                           || ([secondPart isEqualToStringCaseInsensitive:@"0"]))
                        {
                            ni = 0;
                        }
                        else if(([secondPart isEqualToStringCaseInsensitive:@"national"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"nat"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"2"]))
                        {
                            ni = 2;
                        }
                        else if(([secondPart isEqualToStringCaseInsensitive:@"spare"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"international-spare"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"int-spare"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"spare"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"1"]))
                        {
                            ni = 1;
                        }
                        else if(([secondPart isEqualToStringCaseInsensitive:@"reserved"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"national-reserved"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"nat-reserved"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"reserved"])
                                || ([secondPart isEqualToStringCaseInsensitive:@"3"]))
                        {
                            ni = 3;
                        }
                    }
                    else if([firstPart isEqualToString:@"SLS/SLC"])
                    {
                        sscanf(secondPart.UTF8String,"%03X",&sls_slc);
                    }
                    else if([firstPart isEqualToString:@"OPC"])
                    {
                        sscanf(secondPart.UTF8String,"%06X",&opc);
                        NSLog(@"OPC 0x%@=%d",secondPart,opc);

                    }
                    else if([firstPart isEqualToString:@"DPC"])
                    {
                        sscanf(secondPart.UTF8String,"%06X",&dpc);
                        NSLog(@"DPC 0x%@=%d",secondPart,dpc);
                    }
                    else if([firstPart isEqualToString:@"Hex SigMsg"])
                    {
                        pdu  = [[secondPart substringFromIndex:33] unhexedData];
                        NSLog(@"PDUC %@=%@",secondPart,pdu);

                        write=YES;
                    }

                }
            }
            if(write)
            {
                write=NO;
                struct timeval tv;
                memset(&tv,0x00,sizeof(tv));
                char ts[21];
                struct tm trec;
                strncpy(ts, timestamp.UTF8String,sizeof(ts));
                ts[20] = '\0';
                sscanf(ts,"%04d-%02d-%02d %02d:%02d:%02d",
                           &trec.tm_year,
                           &trec.tm_mon,
                           &trec.tm_mday,
                           &trec.tm_hour,
                           &trec.tm_min,
                           &trec.tm_sec);
                trec.tm_year = trec.tm_year -1900;
                trec.tm_mon = trec.tm_mon -1;
                time_t t = timegm(&trec);
                tv.tv_sec = t;

                [pf writeItuMtp3Pdu:(NSData *)pdu
                          timestamp:&tv
                                 si:sio
                                 ni:ni
                                sls:sls_slc
                                opc:opc
                                dpc:dpc];
            }
        }
        [pf close];
    }
    return 0;
}
