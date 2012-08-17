//
//  ASIFormDataRequest+OAuth.m
//
//  Created by Scott James Remnant on 6/3/11.
//  Copyright 2011 Scott James Remnant <scott@netsplit.com>. All rights reserved.
//

#import "ASIFormDataRequest+OAuth.h"


@implementation ASIFormDataRequest (ASIFormDataRequest_OAuth)

- (NSArray *)oauthPostBodyParameters
{
    /*
	if ([fileData count] > 0)
        return nil;
    */

    return postData;
}

- (void)signRequestWithClientIdentifier:(NSString *)consumerKey
                                 secret:(NSString *)consumerSecret
                        tokenIdentifier:(NSString *)tokenKey
                                 secret:(NSString *)tokenSecret
                            usingMethod:(ASIOAuthSignatureMethod)signatureMethod
{
    [self addPostValue:@"1.0" forKey:@"oauth_version"];
    [self addPostValue:consumerKey forKey:@"oauth_consumer_key"];
    [self addPostValue:tokenKey forKey:@"oauth_token"];
    [self addPostValue:@"HMAC-SHA1" forKey:@"oauth_signature_method"];

    NSArray *array = [NSArray arrayWithArray:[ASIHTTPRequest oauthGenerateTimestampAndNonce]];
    NSDictionary *d = [array objectAtIndex:0];
    [self addPostValue:[d objectForKey:@"value"] forKey:@"oauth_timestamp"];
    d = [array objectAtIndex:1];
    [self addPostValue:[d objectForKey:@"value"] forKey:@"oauth_nonce"];

    // Sort by name and value
    NSMutableArray *parameters = [NSMutableArray arrayWithArray:[self oauthPostBodyParameters]];

    [parameters sortUsingComparator:^(id obj1, id obj2) {
        NSDictionary *val1 = obj1, *val2 = obj2;
        NSComparisonResult result = [[val1 objectForKey:@"key"] compare:[val2 objectForKey:@"key"] options:NSLiteralSearch];
        if (result != NSOrderedSame)
            return result;

        return [[val1 objectForKey:@"value"] compare:[val2 objectForKey:@"value"] options:NSLiteralSearch];
    }];

    // Join components together
    NSMutableArray *parameterStrings = [NSMutableArray array];
    for (NSDictionary *parameter in parameters)
    {
        [parameterStrings addObject:[NSString stringWithFormat:@"%@=%@", [parameter objectForKey:@"key"], [[parameter objectForKey:@"value"] encodeForURL]]];
    }

    NSString *urlString = [[self url] absoluteString];
    NSString *baseString = [NSString stringWithFormat:@"%@&%@&%@", [[self requestMethod] uppercaseString], [urlString encodeForURL], [[parameterStrings componentsJoinedByString:@"&"] encodeForURL]];

    NSString *signature = [ASIHTTPRequest oauthGenerateHMAC_SHA1SignatureFor:baseString withClientSecret:consumerSecret andTokenSecret:tokenSecret];

    [self addPostValue:signature forKey:@"oauth_signature"];
}

@end
