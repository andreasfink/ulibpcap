//
//  main.m
//  dump-mtp3
//
//  Created by Andreas Fink on 19.07.16.
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
            fprintf(stderr,"Usage: dump-mtp3 filename  pdu-hex-bytes pdu-hex-bytes ...\n");
            exit(-1);
        }
        UMPCAPFile *pf = [[UMPCAPFile alloc]init];
        pf.filename = @(argv[1]);
        if([pf openForMtp3])
        {
            
        }
        else
        {
            fprintf(stderr,"couldnt open file %s\n",argv[1]);
            exit(-1);
        }
        int idx;
        for(idx=2;idx<argc;idx++)
        {
            NSString *hex = @(argv[idx]);
            NSData *d =[hex dataUsingEncoding:NSUTF8StringEncoding];
            [pf writePdu:[d unhexedData]];
        }
        [pf close];
    }
    return 0;
}
