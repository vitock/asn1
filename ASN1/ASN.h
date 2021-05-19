//
//  ASN1Parser.h
//  GTGJ2
//
//  Created by wei li on 2021/5/12.
//  Copyright © 2021 HUOLI. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface GTASN1Parser : NSObject
- (instancetype)initWithData:(NSData *)data;

- (BOOL)isCA;
- (BOOL)hasnDomain:(NSString *)strDomain;


- (NSString *)cname;
- (NSString *)issuername;
- (void)test;
@end


BOOL  test2();
NS_ASSUME_NONNULL_END
