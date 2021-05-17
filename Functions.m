//
//  Functions.m
//  1Life
//
//  Created by wei li on 2020/12/4.
//

#import "Functions.h"

id dicGetObject(NSDictionary *dic, id aKey, Class aClass) {
    if  (aKey == nil){
        return nil;
    }
    id result = [dic objectForKey:aKey];
    if ( result && [result isKindOfClass:aClass] ) {
        return result;
    }
    return nil;
}

NSDictionary * dicGetDic(NSDictionary *dic, id aKey)
{
    return (NSDictionary *)dicGetObject(dic, aKey, [NSDictionary class]);
}

NSMutableDictionary * dicGetMutableDic(NSDictionary *dic, id aKey)
{
    return (NSMutableDictionary *)dicGetObject(dic, aKey, [NSMutableDictionary class]);
}

NSString * dicGetString(NSDictionary *dic, id aKey)
{
 
    if  (aKey == nil){
        return nil;
    }
    
    id result = [dic objectForKey:aKey];
    if ( result && [result isKindOfClass:[NSString class]] ) {
        return result;
    }
    else if ( result && [result isKindOfClass:[NSNumber class]] ) {
        NSNumber *n = (NSNumber *)result;
        return [n stringValue];
    }
    
    return nil;
    
}

NSString *dicGetNoNullString(NSDictionary *dic, id aKey) {
    NSString *result = dicGetString(dic, aKey);
    if (result) {
        return result;
    }
    return @"";
}

int dicGetInt(NSDictionary *dic, id aKey, int nDefault) {
    id result = [dic objectForKey:aKey];
    if ( result && [result isKindOfClass:[NSNumber class]] ) {
        return [(NSNumber *)result intValue];
    }
    else if ( result && [result isKindOfClass:[NSString class]] ) {
        return [(NSString *)result intValue];
    }
    
    return nDefault;
    
}

float dicGetFloat(NSDictionary *dic, id aKey, float fDefault)
{
    id result = [dic objectForKey:aKey];
    if ( result && [result isKindOfClass:[NSNumber class]] ) {
        return [(NSNumber *)result floatValue];
    }
    else if ( result && [result isKindOfClass:[NSString class]] ) {
        return [(NSString *)result floatValue];
    }
    
    return fDefault;
    
}


NSArray * dicGetArray(NSDictionary *dic, id aKey)
{
    return (NSArray *)dicGetObject(dic, aKey, [NSArray class]);
}



@implementation NSMutableDictionary (safe_setObject)

- (void)safe_setObject:(id)anObject forKey:(id<NSCopying>)aKey {
    if ( aKey ) {
        if ( anObject==nil ) {
            [self removeObjectForKey:aKey];
        }
        else {
            /// 同一个
            [self setObject:anObject forKey:aKey];
        }
    }
}

@end



id arrGetObject(NSArray *arr, NSUInteger index, Class aClass) {
    NSDictionary *result = nil;
    if ( index<arr.count ) {
        result = [arr objectAtIndex:index];
        if ( result && [result isKindOfClass:aClass] ) {
            return result;
        }
    }
    return nil;
}

NSString *arrGetString(NSArray *arr, NSUInteger index)
{
    return arrGetObject(arr, index, [NSString class]);
}

NSDictionary * arrGetDic(NSArray *arr, NSUInteger index) {
    return arrGetObject(arr, index, [NSDictionary class]);
}




@implementation NSMutableArray (OpenetExt)

-(void)safe_addObject:(id)anObject {
    if ( anObject ) {
        [self addObject:anObject];
    }
}

@end
