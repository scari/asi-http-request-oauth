//
//  ASIFormDataRequest+OAuth.h
//
//  Created by Scott James Remnant on 6/3/11.
//  Copyright 2011 Scott James Remnant <scott@netsplit.com>. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "ASIFormDataRequest.h"
#import "ASIHTTPRequest+OAuth.h"
#import "NSData+Base64.h"
#import "NSString+URLEncode.h"

@interface ASIFormDataRequest (ASIFormDataRequest_OAuth)

- (NSArray *)oauthPostBodyParameters;
- (void)signRequestWithClientIdentifier:(NSString *)consumerKey
                                 secret:(NSString *)consumerSecret
                        tokenIdentifier:(NSString *)tokenKey
                                 secret:(NSString *)tokenSecret
                            usingMethod:(ASIOAuthSignatureMethod)signatureMethod;
@end
