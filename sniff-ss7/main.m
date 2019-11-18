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

int main(int argc, const char * argv[])
{
    NSString *email = NULL;
    


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
                                               @"help"  : @"the device to sniff on",
                                           },
                                           @{
                                               @"name"  : @"filter",
                                               @"short" : @"-f",
                                               @"long"  : @"--filter",
                                               @"help"  : @"the capture filter rule",
                                           },
                                           @{
                                               @"name"  : @"host",
                                               @"short" : @"-h",
                                               @"long"  : @"--host",
                                               @"argument" : @"destination host",
                                               @"help"  : @"destination host to where the syslog packets will be sent",
                                               },
                                               @{
                                               @"name"  : @"port",
                                               @"short" : @"-p",
                                               @"long"  : @"--port",
                                               @"help"  : @"UDP port",
                                               }];

        UMCommandLine *_commandLine = [[UMCommandLine alloc]initWithCommandLineDefintion:commandLineDefinition
                                                                           appDefinition:appDefinition
                                                                                    argc:argc
                                                                                    argv:argv];

        [_commandLine handleStandardArguments];
        NSDictionary *params = _commandLine.params;
        NSString *encryptionKey = NULL;
        NSString *signatureKey = NULL;
        BOOL verbose=NO;
        NSString *hostName;
        
        if(params[@"verbose"])
        {
            verbose = YES;
        }
        NSArray *a = params[@"host"];
        if(a.count  > 0)
        {
            for(NSString *h in a)
            {
                NSError *err =NULL;;
                
                NSString *key = [NSString stringWithContentsOfFile:filename encoding:NSUTF8StringEncoding error:&err];
                if(key)
                {
                    encryptionKey = key;
                }
            }
        }
        else
        {
            NSError *err = NULL;
            encryptionKey = [NSString stringWithContentsOfFile:@"/opt/uliblicense/encryption.key" encoding:NSUTF8StringEncoding error:&err];
            if(err)
            {
                NSLog(@"%@",err);
            }
        }

        a = params[@"signature-key"];
        if(a.count > 0)
        {
            for(NSString *filename in a)
            {
                NSError *err =NULL;
                NSString *key = [NSString stringWithContentsOfFile:filename encoding:NSUTF8StringEncoding error:&err];
                if(err)
                {
                    NSLog(@"%@",err);
                }
                if(key)
                {
                    signatureKey = key;
                }
            }
        }
        else
        {
            NSError *err = NULL;
            signatureKey = [NSString stringWithContentsOfFile:@"/opt/uliblicense/sign.key" encoding:NSUTF8StringEncoding error:&err];
            if(err)
            {
                NSLog(@"%@",err);
            }
        }
        
        
        if(params[@"email"])
        {
            NSArray *emails = params[@"email"];
            if(emails.count > 0)
            {
                email = emails[0];
                mmlicense.licenseEmail = email;
            }
        }

        if(params[@"output"])
        {
            NSArray *filenames = params[@"output"];
            for(NSString *filename in filenames)
            {
                licenseFileName = filename;
            }
        }

        if(params[@"cpu-id"])
        {
            NSArray *entries = params[@"cpu-id"];
            for(NSString *entry in entries)
            {
                UMLicenseRestriction *lr = [[UMLicenseRestriction alloc]init];
                lr.lockedToCpuId = entry;
                [licenseRestrictions addRestriction:lr];
            }
        }

        if(params[@"mac-addr"])
        {
            NSArray *entries = params[@"mac-addr"];
            for(NSString *entry in entries)
            {
                UMLicenseRestriction *lr = [[UMLicenseRestriction alloc]init];
                lr.lockedToMacAddress = entry;
                [licenseRestrictions addRestriction:lr];
            }
        }
        if(params[@"ip-addr"])
        {
            NSArray *entries = params[@"ip-addr"];
            for(NSString *entry in entries)
            {
                UMLicenseRestriction *lr = [[UMLicenseRestriction alloc]init];
                lr.lockedToIp= entry;
                [licenseRestrictions addRestriction:lr];
            }
        }
        if(params[@"os"])
        {
            NSArray *entries = params[@"os"];
            for(NSString *entry in entries)
            {
                UMLicenseRestriction *lr = [[UMLicenseRestriction alloc]init];
                lr.lockedToOperatingSystem= entry;
                [licenseRestrictions addRestriction:lr];
            }
        }
        if(params[@"serial"])
        {
            NSArray *entries = params[@"serial"];
            for(NSString *entry in entries)
            {
                licenseFile[@"serial"] = entry;
                UMLicenseRestriction *lr = [[UMLicenseRestriction alloc]init];
                lr.lockedToSerial= entry;
                [licenseRestrictions addRestriction:lr];
            }
        }

        if(params[@"demo"])
        {
            NSArray *demos = params[@"demo"];
            for(NSString *demo in demos)
            {
                int days  = [demo intValue];
                
                time_t current;
                time(&current);
                current = current + (24*60*60*days);
                
                struct tm trec;
                struct    timeval  tp;
                struct    timezone tzp;
                gettimeofday(&tp, &tzp);
                gmtime_r(&current, &trec);
                expiration = [NSString stringWithFormat:@"%04d-%02d-%02d %02d:%02d:%02d.%06d",
                              trec.tm_year+1900,
                              trec.tm_mon+1,
                              trec.tm_mday,
                              trec.tm_hour,
                              trec.tm_min,
                              trec.tm_sec,
                              (int)tp.tv_usec];
                expirationDate = [NSDate dateWithTimeIntervalSinceNow:(NSTimeInterval)(24*60*60*days)];
                mmlicense.licenseType = @"temporary";
                mmlicense.licenseExpiration = expirationDate;
            }
        }
        if(params[@"renew-url"])
        {
            NSArray *urls = params[@"renew-url"];
            for(NSString *url in urls)
            {
                mmlicense.licenseType = @"renewing";
                mmlicense.licenseRenewUrl = url;
                mmlicense.licenseRenewTimerMin = @(7*24*60*60); /* min once a week */
                mmlicense.licenseRenewTimerMax = @(31*24*60*60); /* max one per month */
                mmlicense.licenseRenewAddress = @"+41587079921";
            }
        }
        if(params[@"report-url"])
        {
            NSArray *urls = params[@"report-url"];
            for(NSString *url in urls)
            {
                mmlicense.licenseReportUrl = url;
                mmlicense.licenseReportAddress = @"+41587079922";
                mmlicense.licenseReportTimer = @(7*24*60*60); /* report once a week */
            }
        }
        else
        {
            mmlicense.licenseReportUrl = @"https://license.messagemover.com/report.php";
            mmlicense.licenseReportAddress = @"+41587079922";
            mmlicense.licenseReportTimer = @(7*24*60*60); /* report once a week */
        }
        if(params[@"renew-address"])
        {
            NSArray *nrs = params[@"renew-address"];
            for(NSString *nr in nrs)
            {
                mmlicense.licenseType = @"renewing";
                mmlicense.licenseRenewAddress= nr;
            }
        }

        if(params[@"install"])
        {
            doInstall = YES;
            if(verbose)
            {
                NSLog(@"doInstall=yes");
            }
        }
        if(params[@"legacy"])
        {
            doLegacy = YES;
            if(verbose)
            {
                NSLog(@"legacy=yes");
            }
        }

        if(params[@"smpp"])
        {
            ADD_PRODUCT_ALL(@"smpp");
        }
        
        if(params[@"emi-ucp"])
        {
            ADD_PRODUCT_ALL(@"emi-ucp");
        }
        if(params[@"m3ua"])
        {
            ADD_PRODUCT_ALL(@"m3ua");
        }
        if(params[@"http"])
        {
            ADD_PRODUCT_ALL(@"http");
        }
        if(params[@"http-hlr"])
        {
            ADD_PRODUCT_ALL(@"http-hlr");
        }
        if(params[@"mofwd"])
        {
            ADD_PRODUCT_ALL(@"mofwd");
        }
        if(params[@"quota"])
        {
            ADD_PRODUCT_ALL(@"quota");
        }
        if(params[@"interworking"])
        {
            ADD_PRODUCT_ALL(@"interworking");
        }
        if(params[@"udp"])
        {
            ADD_PRODUCT_ALL(@"udp");
        }
        if(params[@"diameter"])
        {
            ADD_PRODUCT_ALL(@"diameter");
        }
        if(params[@"tcap"])
        {
            ADD_PRODUCT_ALL(@"tcap");
        }
        if(params[@"gsmmap"])
        {
            ADD_PRODUCT_ALL(@"gsmmap");
        }
        if(params[@"m2pa"])
        {
            ADD_PRODUCT_ALL(@"m2pa");
        }
        if(params[@"mtp3"])
        {
            ADD_PRODUCT_ALL(@"mtp3");
        }

        if(params[@"expiration"])
        {
            NSArray *expirations = params[@"expiration"];
            for(NSString *expiration in expirations)
            {
                expirationDate = [NSDate dateWithStandardDateString:expiration];
                if(expirationDate==NULL)
                {
                    fprintf(stderr,"Can not interpret date '%s'. Please use format 'yyyy-MM-dd HH:mm:ss.SSSS'\n",expiration.UTF8String);
                    exit(-1);
                }
                mmlicense.licenseType = @"temporary";
                mmlicense.licenseExpiration = expirationDate;
            }
        }
        if(params[@"license-number"])
        {
            NSArray *lns = params[@"license-number"];
            for(NSString *ln in lns)
            {
                licenseNumber = ln;
                mmlicense.licenseSerialNumber = licenseNumber;
            }
        }
        if(params[@"license-name"])
        {
            
            NSArray *lns = params[@"license-name"];
            for(NSString *ln in lns)
            {
                licenseName = ln;
                mmlicense.licenseOwner = licenseName;
            }
        }
        if(params[@"smsc"])
        {
            licenseFeatures[@"smsc"] = @{@"enable": @"YES"};
            [mmlicense addProduct:smsc];

        }
        if(params[@"smsproxy"])
        {
            licenseFeatures[@"smsproxy"] = @{@"enable": @"YES"};
            [mmlicense addProduct:smsproxy];
        }
        if(params[@"ss7firewall"])
        {
            licenseFeatures[@"ss7firewall"] = @{@"enable": @"YES"};

            ss7firewall
            [mmlicense addProduct:ss7firewall];
        }
        if(params[@"smsfirewall"])
        {
            licenseFeatures[@"smsfirewall"] = @{@"enable": @"YES"};
            [mmlicense addProduct:smsfirewall];
        }

        if(params[@"cnam-server"])
        {
            licenseFeatures[@"cnam-server"] = @{@"enable": @"YES"};
            [mmlicense addProduct:cnam_server];
        }
        if(params[@"simproxy"])
        {
            licenseFeatures[@"simproxy"] = @{@"enable": @"YES"};
            [mmlicense addProduct:simproxy];
        }
        if(params[@"hlrclient"])
        {
            licenseFeatures[@"hlrclient"] = @{@"enable": @"YES"};
            [mmlicense addProduct:simproxy];
        }
        if(params[@"eirproxy"])
        {
            licenseFeatures[@"eirproxy"] = @{@"enable": @"YES"};
            [mmlicense addProduct:simproxy];
        }
        if(params[@"rerouter"])
        {
            licenseFeatures[@"rerouter"] = @{@"enable": @"YES"};
            [mmlicense addProduct:rerouter];
        }
        if(params[@"diameter-edge-agent"])
        {
            [diameter_dea addFeatureWithName:@"diameter-edge-agent"];
            [estp addFeatureWithName:@"diameter-edge-agent"];
            [diameter_dea addFeatureWithName:@"diameter"];
            [estp addFeatureWithName:@"diameter"];
            [mmlicense addProduct:diameter_dea];
        }
        if(params[@"diameter-routing-agent"])
        {
            [diameter_dra addFeatureWithName:@"diameter-routing-agent"];
            [estp addFeatureWithName:@"diameter-routing-agent"];
            [diameter_dra addFeatureWithName:@"diameter"];
            [estp addFeatureWithName:@"diameter"];
            [mmlicense addProduct:diameter_dra];
        }

        if(params[@"map-api-server"])
        {
            [map_api addFeatureWithName:@"map-api-server"];
            [estp addFeatureWithName:@"map-api-server"];
            [mmlicense addProduct:map_api];
        }
        if(params[@"camel-api-server"])
        {
            [camel_api addFeatureWithName:@"camel-api-server"];
            [estp addFeatureWithName:@"camel-api-server"];
            [mmlicense addProduct:camel_api];
        }

        if(params[@"diameter-api-server"])
        {
            [diameter_api addFeatureWithName:@"diameter-api-server"];
            [estp addFeatureWithName:@"diameter-api-server"];
            [mmlicense addProduct:diameter_api];
        }



        if(params[@"estp"])
        {
            licenseFeatures[@"estp"] = @{@"enable": @"YES"};
            [estp addFeatureWithName:@"estp"];
            [mmlicense addProduct:estp];
        }

        licenseFile[@"features"] = licenseFeatures;


        mmlicense.licenseRestrictions = licenseRestrictions;

        if(doLegacy)
        {
            unlink("license.plist");
            unlink("license.bin");
            [licenseFile writeToFile:@"license.plist" atomically:NO];

            NSData *licenseData = [NSData dataWithContentsOfFile:@"license.plist"];
            UMLegacyLicense *llic = [[UMLegacyLicense alloc]init];
            llic.plaintext = licenseData;
            [llic encrypt];
            NSData *chiphertext = llic.ciphertext;
            if(doInstall)
            {
                NSString *licenseInstallFileName = @"/etc/messagemover/license.bin";
                NSLog(@"Installing license to %@",licenseInstallFileName);
                [chiphertext writeToFile:licenseInstallFileName atomically:YES];
            }
            NSLog(@"writing license to %@",licenseFileName);
            [chiphertext writeToFile:licenseFileName atomically:YES];

            NSData *verifyData = [NSData dataWithContentsOfFile:licenseFileName];
            llic.ciphertext = verifyData;
            [llic decrypt];
            NSData *decryptedData = llic.plaintext;
        
            /* we dont want any trailing 0x00 bytes as this confuses GNUStep */
            size_t len = strnlen((void *)decryptedData.bytes, (size_t)decryptedData.length);
            decryptedData = [decryptedData subdataWithRange:NSMakeRange(0,len) ];
            
            NSString *tmpfile = [NSString stringWithFormat:@"/tmp/.mm.%d.plist",getpid()];

            [decryptedData writeToFile:tmpfile atomically:YES];
            NSDictionary *licDict = [NSDictionary dictionaryWithContentsOfFile:tmpfile];
            if(licDict == NULL)
            {
                NSLog(@"Produced result can not be read!\n");
            }else
            {
                NSLog(@"Successfully read\n");
            }
        }
        if(slicense)
        {
            [slicense signLicenseWithRSAPublicKey:signatureKey];

            NSString *licenseFileName = [NSString stringWithFormat:@"%@.license",slicense.license.licenseSerialNumber];
            if(encryptionKey)
            {
                [slicense encryptLicenseWithRSAPublicKey:encryptionKey];
            }
            NSData *data = [slicense berEncoded];
            NSLog(@"writing new license to %@",licenseFileName);
            [data writeToFile:licenseFileName atomically:YES];
        }
    }
    return 0;
}

