//
//  Functions.h
//  1Life
//
//  Created by wei li on 2020/12/4.
//



#import <Foundation/Foundation.h>

id dicGetObject(NSDictionary *dic, id aKey, Class aClass);
NSDictionary * dicGetDic(NSDictionary *dic, id aKey);
NSMutableDictionary * dicGetMutableDic(NSDictionary *dic, id aKey);
NSString * dicGetString(NSDictionary *dic, id aKey);
NSString *dicGetNoNullString(NSDictionary *dic, id aKey) ;
int dicGetInt(NSDictionary *dic, id aKey, int nDefault);
float dicGetFloat(NSDictionary *dic, id aKey, float fDefault);
NSArray * dicGetArray(NSDictionary *dic, id aKey);


@interface  NSMutableDictionary (safe_setObject)
- (void)safe_setObject:(id)anObject forKey:(id<NSCopying>)aKey ;
@end



id arrGetObject(NSArray *arr, NSUInteger index, Class aClass) ;
NSString *arrGetString(NSArray *arr, NSUInteger index);
NSDictionary * arrGetDic(NSArray *arr, NSUInteger index);



@interface NSMutableArray (OpenetExt)

-(void)safe_addObject:(id)anObject ;
@end
