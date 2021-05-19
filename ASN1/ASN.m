//
//  ASN1Parser.m
//  GTGJ2
//
//  Created by wei li on 2021/5/12.
//  Copyright © 2021 HUOLI. All rights reserved.
//
#define MSGPrefix ""
#define MYLOGINFO NSLog
#define metamacro_head(FIRST, ...) FIRST
#define metamacro_at20(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19,...) metamacro_head(__VA_ARGS__)

#define metamacro_is_only_one(...) \
metamacro_at20( __VA_ARGS__, 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0)
#define _MyLogFunc0(fmt)   MYLOGINFO((@"%s %s:%d  " fmt),MSGPrefix,__FUNCTION__,__LINE__  )
#define _MyLogFunc1(fmt,...)   MYLOGINFO((@"%s %s:%d  " fmt),MSGPrefix,__FUNCTION__,__LINE__ ,__VA_ARGS__ )

#define MyCAT(A,B) MyCAT__(A,B)
#define MyCAT__(A,B) A##B
#define GTLog(...)  MyCAT(_MyLogFunc,metamacro_is_only_one(__VA_ARGS__) )(__VA_ARGS__)



#import "ASN.h"
#import "Functions.h"
#include <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

typedef struct {
    int len;     // 长度
    int lenLen;  // 长度所占的长度
} GTLenData;     // 长度信息
typedef uint8_t byte;

// 长度、长度占用
GTLenData gtgetLen(const byte* data, int i) {
    GTLenData res;
    res.lenLen = 1;
    if (data[i] & 0x80) {
        int len_len = data[i] & 0x7f;
        int len = 0;
        i++;
        for (int j = 0; j < len_len; j++) {
            len <<= 8;
            len += data[i + j];
        }
        res.len = len;
        res.lenLen += len_len;
    } else {
        res.len = data[i] & 0x7f;
    }
    return res;
}



@interface  GTASN1Item:NSObject{
}   // 解析项目

@property(nonatomic, strong)NSString *title;
@property(nonatomic, assign)int len;
@property(nonatomic, assign)int type;

@property(nonatomic, strong)NSData *data;

@end

@implementation GTASN1Item
@end




void gtparseANS(const byte* data, int begin, int end,NSMutableArray <GTASN1Item*> *ansData) ;

@interface GTASN1Parser(){
    NSString *cname;
    NSString *issuer;
    
    
    int _parseIndex ;
}
@property(nonatomic, strong)NSMutableArray *ansData;

@property(nonatomic, strong)NSData *orginData;
@end
@implementation GTASN1Parser

- (instancetype)initWithData:(NSData *)data{
    self = [super init];
    if (self ) {
        self.ansData = [NSMutableArray new];
        _parseIndex= 0;
        [self gtparseANS:data.bytes begin:0 end: data.length ansData:self.ansData];
    }
    return self;
}
- (NSString *)cname{
    //2.5.4.3 06
    if (cname) {
        return cname;
    }
    
    
    return nil;
}

- (NSString *)issuername{
    if (issuer) {
        return issuer;
    }
    
    return nil;
}

/**
 * 1 yes
 * 0 no
 * -1 unknown
 */
- (int )_checkIsCA:(NSArray *)arrItems{
    for (int i = (int)arrItems.count -1 ; i >=0; -- i ) {
        id item2 = arrGetObject(arrItems, i , [NSObject class]);
        GTASN1Item *item = item2;
        if ([item isKindOfClass:[GTASN1Item class]] &&  [item.title isEqualToString:@"2.5.29.19"]) {
            
            i ++ ;
            GTASN1Item *item2 = arrGetObject(arrItems, i , [GTASN1Item class]);
            if (item2 && item2.type == 0x01) {
                return [item2.title isEqualToString:@"True"];
            }
            return 0;
        }
        else if([item isKindOfClass:[NSArray class]]){
            
            int findCaKey  = [self _checkIsCA:(NSArray *)item];
            if (findCaKey >= 0) {
                return findCaKey;
            }
        }
    }
    
    /// 没找到
    return -1;
}

- (BOOL)isCA{
    return [self _checkIsCA:self.ansData] == 1;
    
}

- (void)testPrintArray:(NSArray *)arr level:(int )l {
    
    printf("\n%*s[",l,"");
    for (GTASN1Item * itm in arr) {
        if ([itm isKindOfClass:[NSArray class]]) {
            [self testPrintArray:itm level:l + 4];
            continue;;
        }
        printf("\n%*s%s %02x %s",l + 4 ,">",[itm.title UTF8String],itm.type,[[itm.data description] UTF8String]);
    }
    printf("\n%*s]",l,"");
}

- (void)test{
    GTLog(@"222");
    printf("\n\n");
    [self testPrintArray:self.ansData level:0];
    printf("\n\n");
}

/*
  
 2.5.29.17  Subject alernate name 主替换名称 dns name
NSDictionary *titleToString = @{
    @"1.3.6.1.5.5.7.3.1":@"服务器身份验证(id_kp_serverAuth): True",
    @"1.3.6.1.5.5.7.3.2": @"客户端身份验证(id_kp_clientAuth): True",
    @"2.5.29.37":@"扩展密钥用法(Extended key usage):",
    @"2.5.29.31": @"CRL Distribution Points:",
    @"1.2.840.10045.2.1":@"EC Public Key:",
    @"Extension":@"扩展字段:",
    @"2.23.140.1.2.2":@"组织验证(organization-validated):",
    @"1.3.6.1.5.5.7.1.1":@"AuthorityInfoAccess:",
    @"2.5.29.19":@"基本约束(Basic Constraints):",
 
    
    @"1.3.6.1.5.5.7.3.2":@"客户端身份验证(id_kp_clientAuth): True"};
NSDictionary *titleToHex = @{
    @"1.2.840.10045.3.1.7":
        @"推荐椭圆曲线域(SEC 2 recommended elliptic curve domain): \n",
@"2.5.29.35": @"授权密钥标识符(Authority Key Identifier): ",
@"2.5.29.14": @"主体密钥标识符(Subject Key Identifier): "};
NSDictionary *titleToNext = @{
    @"1.3.6.1.5.5.7.2.1":@"OID for CPS qualifier: ",
    @"1.3.6.1.5.5.7.48.1":@"OCSP: ",
    @"1.3.6.1.5.5.7.48.2": @"id-ad-caIssuers: ",
    @"1.3.6.1.4.1.311.60.2.1.1": @"所在地(Locality): ",
    @"1.3.6.1.4.1.311.60.2.1.3": @"国家(Country): ",
    @"1.3.6.1.4.1.311.60.2.1.2": @"州或省(State or province): ",
    @"2.5.4.3": @"通用名称(id-at-commonName): ",
    @"2.5.4.5": @"颁发者序列号(id-at-serialNumber): ",
    @"2.5.4.6": @"颁发者国家名(id-at-countryName): ",
    @"2.5.4.7": @"颁发者位置名(id-at-localityName): ",
    @"2.5.4.8": @"颁发者州省名(id-at-stateOrProvinceName): ",
    @"2.5.4.9": @"颁发者街区地址(id-at-streetAddress): ",
    @"2.5.4.10": @"颁发者组织名(id-at-organizationName): ",
    @"2.5.4.11": @"颁发者组织单位名(id-at-organizationalUnitName): ",
    @"2.5.4.12": @"颁发者标题(id-at-title): ",
    @"2.5.4.13": @"颁发者描述(id-at-description): ",
    @"2.5.4.15": @"颁发者业务类别(id-at-businessCategory): ",
    @"2.5.29.32": @"证书策略(Certificate Policies): ",
    @"2.5.29.15": @"使用密钥(Key Usage): "};

NSDictionary *algorithmObject = @{
    @"1.2.840.10040.4.1" : @"DSA",
    @"1.2.840.10040.4.3" : @"sha1DSA",
    @"1.2.840.113549.1.1.1" :@"RSA",
    @"1.2.840.113549.1.1.2" : @"md2RSA",
    @"1.2.840.113549.1.1.3" : @"md4RSA",
    @"1.2.840.113549.1.1.4" : @"md5RSA",
    @"1.2.840.113549.1.1.5" : @"sha1RSA",
    @"1.3.14.3.2.29": @"sha1RSA",
    @"1.2.840.113549.1.1.13": @"sha512RSA",
    @"1.2.840.113549.1.1.11": @"sha256RSA"};
;

 */

- (NSArray *)_findSAN:(NSString *)strDomain inArray:(NSArray *)arrAnsData{
    
    for (int i = 0 ; i < arrAnsData.count; ++ i ) {
        id itme0 = arrGetObject(arrAnsData, i , [NSObject class]);
        GTASN1Item *item = itme0;
        if ([item isKindOfClass:[GTASN1Item class]] &&  [item.title isEqualToString:@"2.5.29.17"]) {
            i ++ ;
            NSMutableArray *arrDomains = [NSMutableArray new];
            id next = arrGetObject(arrAnsData, i , [NSObject class]);
            
            if ([next isKindOfClass:[NSArray class]]) {
                NSArray *arrSans = next ;
                int j = 0;
                GTASN1Item *item2 =  arrGetObject(arrSans, j   , [GTASN1Item class]);
                while (item2 && item2.type == 0x82) {
                    if (item2.title.length) {
                        [arrDomains safe_addObject:item2.title];
                    }
                    j ++;
                    item2 = arrGetObject(arrSans, j   , [GTASN1Item class]);
                    
                }
                i--;
                return arrDomains;
            }
            else{
                GTASN1Item *item2 = arrGetObject(arrAnsData, i , [GTASN1Item class]);
                while (item2 && item2.type == 0x82) {
                    if (item2.title.length) {
                        [arrDomains safe_addObject:item2.title];
                    }
                    i ++;
                    item2 = arrGetObject(arrAnsData, i , [GTASN1Item class]);
                    
                }
                i--;
                return arrDomains;
            }
           
            
            
        }
        else if([item isKindOfClass:[NSArray class]]){
            id z = [self _findSAN:strDomain  inArray:item];
            if (z) {
                return z;
            }
        }
    }
    
    return nil;
}


- (BOOL)hasnDomain:(NSString *)strDomain{
    
    NSArray *arrDomains = [self  _findSAN:strDomain inArray:self.ansData];
    GTLog(@"%@",arrDomains);
  
    for (NSString *san in arrDomains) {
        NSString *san2 = [san stringByReplacingOccurrencesOfString:@"*" withString:@""];
        
        // 防止 sscc.com 的匹配到  rsscc.com
        if ([san2 hasPrefix:@"."] && [strDomain hasSuffix:san2]) {
            return YES;
        }
        else if([strDomain isEqualToString:san2]){
            return YES;
        }
    }
    
 
    
    return NO;

}


- (void)gtparseANS:(const byte*) data  begin:(int) begin end:(int) end ansData:(NSMutableArray <GTASN1Item *> *) ansData {
    _parseIndex ++;
    
    
    // cout << "parse" << begin << "-" << end << endl;
    int i = begin;
    GTLenData lens;
    int oiFirst;
    int oiIndex;
    NSString *title;
    while (i < end) {
        int type = data[i];
        i++;
        lens = gtgetLen(data, i);
        if (i + lens.lenLen <= end) {
            i += lens.lenLen;
        }
        if (lens.len <0 || i + lens.len > end) {
            break;
        }
        title = @"";
        switch (type) {
            case 0x30:  // 结构体序列
            {
                if (_parseIndex == 2) {
                    self.orginData = [[NSData alloc] initWithBytes:data+i - lens.lenLen -1 length:lens.len + lens.lenLen + 1 ];
                    GTLog(@"%d", lens.len);
                }
                NSMutableArray *arrSeq = [NSMutableArray new];
                [self gtparseANS:data  begin:i  end:i + lens.len ansData:arrSeq];
                [ansData safe_addObject:arrSeq];
//                gtparseANS(data, i, i + lens.len,ansData);
                break;
            }
                
            case 0x31:  // Set序列
            {
                NSMutableArray *arrSeq = [NSMutableArray new];
                [self gtparseANS:data  begin:i  end:i + lens.len ansData:arrSeq];
                [ansData safe_addObject:arrSeq];
                //                gtparseANS(data, i, i + lens.len,ansData);
                break;
            
            }
               
                
            case 0xa3:  // 扩展字段
            {
                title = @"Extension";
                
                GTASN1Item *itm = [GTASN1Item new];
                itm.title = title;
                itm.len = lens.len;
                itm.type = type;
                
                [ansData addObject:itm];
//                gtparseANS(data, i, i + lens.len,ansData);
                [self gtparseANS:data  begin:i  end:i + lens.len ansData:ansData];
                break;
            }
                
            case 0xa0:  // 证书版本
            {
                title = @"Version";
                GTASN1Item *itm = [GTASN1Item new];
                itm.title = title;
                itm.len = lens.len;
                itm.type = type;
                
//                [ansData addObject:itm];
//                gtparseANS(data, i, i + lens.len,ansData);
                [self gtparseANS:data  begin:i  end:i + lens.len ansData:ansData];
                break;
            }
               
            case 0x04:  // OCTET STRING
            {
//                gtparseANS(data, i, i + lens.len,ansData);
                [self gtparseANS:data  begin:i  end:i + lens.len ansData:ansData];
                
            }
                
                
            case 0x05:
                break;
            case 0x06:  // Object Identifier
            {
                title = @"";
                NSMutableArray *arrComponet = [NSMutableArray new];
                
                oiFirst = data[i] & 0x7f;
                oiIndex = MIN(oiFirst / 40, 2);
                [arrComponet addObject:@(MIN(oiFirst / 40, 2)).stringValue];
                [arrComponet addObject:@"."];
                [arrComponet addObject:@(oiFirst - 40 * oiIndex).stringValue];
                [arrComponet addObject:@"."];
                
                
                oiIndex = 2;
                oiFirst = 0;
                for (int t = 1; t < lens.len; t++) {
                    oiFirst <<= 7;
                    oiFirst += data[i + t] & 0x7f;
                    if (!(data[i + t] & 0x80)) {
                        [arrComponet addObject:@(oiFirst).stringValue];
                        [arrComponet addObject:@"."];
                        oiIndex++;
                        oiFirst = 0;
                    }
                }
                title = [arrComponet componentsJoinedByString:@""];
                
                GTASN1Item *itm = [GTASN1Item new];
                itm.title = [title substringToIndex:title.length -1];
                itm.len = lens.len;
                itm.type = type;
                 
                
                [ansData addObject:itm];
                
                break;
            }
                
            case 0x17:  // 时间戳
                title = @"UTCTime";
            case 0x13:  // 字符串
            case 0x82:  // subjectUniqueID
            case 0x16:  // IA5String类型
            case 0x0c:  // UTF8String类型
            case 0x86:  // 特殊IA5String类型
            {
                NSMutableString *SS = [NSMutableString new];
                [SS appendString:title];
                for (int t = 0; t < lens.len; t++) {
                    [SS appendFormat:@"%C",data[i + t]];
                    
                }
                title = SS;
                GTASN1Item *itm = [GTASN1Item new];
                itm.title = title;
                itm.len = lens.len;
                itm.type = type;
                
                [ansData addObject:itm];
                break;
            }
               
            case 0x01:  // 布尔类型
            {
                oiFirst = 0xff;
                for (int t = 0; t < lens.len; t++) {
                    oiFirst &= data[i + t];
                }
                
                
                GTASN1Item *itm = [GTASN1Item new];
                itm.title = oiFirst == 0 ? @"False" : @"True";
                itm.len = lens.len;
                itm.type = type;
                
                [ansData addObject:itm];
                
                break;
            }
               
            case 0x02:  // 整数类型
            case 0x80:  // 直接输出
            {
                byte *tmp =  malloc(lens.len);
                
                for (int t = 0; t < lens.len; t++) {
                    tmp[t] = data[i + t];
                }
                GTASN1Item *itm = [GTASN1Item new];
                itm.len = lens.len;
                itm.type = type;
                
                itm.data = [NSData dataWithBytes:tmp  length:lens.len];
                free(tmp);
                
                [ansData addObject:itm];
                break;
            }

            case 0x03:  // Bit String 类型
                
            {
                byte *tmp =  malloc(lens.len - 1);
                
                for (int t = 0; t < lens.len -1; t++) {
                    tmp[t] = data[i + t + 1];
                }
                
                GTASN1Item *itm = [GTASN1Item new];
                itm.title = @"";
                itm.len = lens.len;
                itm.type = type;
                
                itm.data = [NSData dataWithBytes:tmp  length:lens.len-1];
                free(tmp);
                
                [ansData addObject:itm];
                break;
            }
                
//                忽略
//                text = new byte[lens.len - 1];
//                for (int t = 0; t < lens.len - 1; t++) {
//                    text[t] = data[i + t + 1];
//                }
//                ansData.push_back({"", lens.len - 1, text, type});
                break;
            case 0x00:
                
            {
                byte *tmp =  malloc(end - begin);
                
                for (int t = begin + 1; t <  end; t++) {
                    tmp[t - begin - 1] = data[t];
                }
                
                GTASN1Item *itm = [GTASN1Item new];
                itm.title = @"0x00";
                itm.len = lens.len;
                itm.type = type;
                
                itm.data = [NSData dataWithBytes:tmp  length:end - begin];
                free(tmp);
                
                [ansData addObject:itm];
                break;
            }
//                忽略
//                text = new byte[end - begin];
//                for (int t = begin + 1; t < end; t++) {
//                    text[t - begin - 1] = data[t];
//                }
//                ansData.push_back({"0x00", end - begin - 1, text, type});
                break;
            default:
                i--;
                if (i + lens.len > end) {
                    byte *tmp =  malloc(end - begin);
                    
                    for (int t = 0; t < end - begin; t++) {
                        tmp[t] = data[i + t];
                    }
                    GTASN1Item *itm = [GTASN1Item new];
                    itm.title = @"0x00";
                    itm.len = lens.len;
                    itm.type = type;
                    
                    itm.data = [NSData dataWithBytes:tmp  length:end - begin];
                    free(tmp);
                    
                    [ansData addObject:itm];
                } else {
                    byte *tmp =  malloc(lens.len);
                    
                    for (int t = 0; t < lens.len; t++) {
                        tmp[t] = data[i + t];
                    }
                    GTASN1Item *itm = [GTASN1Item new];
                    itm.title = @"";
                    itm.len = lens.len;
                    itm.type = type;
                    
                    itm.data = [NSData dataWithBytes:tmp  length:lens.len];
                    free(tmp);
                    
                }
                i = end;
        }
        i += lens.len;
    }
}


- (BOOL)findKey:(NSString *)key target:(id) obj{
    if ([obj isKindOfClass:[GTASN1Item class]]) {
        return  [[(GTASN1Item *)obj title] isEqualToString:key];
    }
    else{
        if ([obj isKindOfClass:[NSArray class]]) {
            for (id obj2 in obj) {
                return [self findKey:key  target:obj2];
            }
        }
    }
    return NO;
}

- (BOOL )isSha1Sign{
    //    1.2.840.113549.1.1.5
     ;
    NSArray *arr = self.ansData.firstObject;
    id obj =  arrGetObject(arr , 1, [NSObject class]);
    return [self findKey:@"1.2.840.113549.1.1.5" target:obj];
}

- (NSData *)signData{

    GTASN1Item *d = self.ansData.lastObject;
    
    while (d && [d isKindOfClass:[NSArray class]]) {
        d = [(NSArray *)d lastObject];
    };
    return d.data;
    
}

/// 获取pulickey 的data
- (NSString *)getPublicKeyRawDataSha1{
    NSArray *arrTop = self.ansData.firstObject;
    NSArray *arrCert = arrTop.firstObject;
    NSArray *arrPub = arrGetObject(arrCert, 6 , [NSArray class]);
    
    GTASN1Item *item = arrGetObject(arrPub, 1, [GTASN1Item class]);
    /// Bit String
//    item.type == 0x03;
    NSData *data = item.data;
    
    uint8_t hashBytes[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1([data bytes], (CC_LONG)[data length], hashBytes);
    NSMutableString *strResult = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    int j = 0 ;
    while (j < CC_SHA1_DIGEST_LENGTH) {
        [strResult appendFormat:@"%02x",hashBytes[j]];
        j ++ ;
    }
    return strResult;
}
@end

 

BOOL gtVerifySignature(NSData* plainData, NSData* signature, SecKeyRef publicKey,BOOL isSha1 )
{
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    const void* signedHashBytes = [signature bytes];

    size_t hashBytesSize = isSha1 ? CC_SHA1_DIGEST_LENGTH : CC_SHA256_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (isSha1) {
        if (!CC_SHA1([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
            
            CFRelease(publicKey);
            return NO;
        }
    }
    else{
        if (!CC_SHA256([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
            
            CFRelease(publicKey);
            return NO;
        }
    }
    
    
  
    OSStatus status = SecKeyRawVerify(publicKey,
                                      isSha1 ? kSecPaddingPKCS1SHA1 : kSecPaddingPKCS1SHA256,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    
    
    
    CFRelease(publicKey);
    return status == errSecSuccess;
}

BOOL  test2(){
    GTLog(@"----------");
    NSString *str =  [[NSString alloc] initWithContentsOfFile:@"/Users/liw003/Downloads/test1.pem" encoding:NSUTF8StringEncoding error:nil];
    str = [str stringByReplacingOccurrencesOfString:@"-----BEGIN CERTIFICATE-----" withString:@""];
    str = [str stringByReplacingOccurrencesOfString:@"-----END CERTIFICATE-----" withString:@""];
    
    NSData *data1 = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    str =  [[NSString alloc] initWithContentsOfFile:@"/Users/liw003/Downloads/test2.pem" encoding:NSUTF8StringEncoding error:nil];
    str = [str stringByReplacingOccurrencesOfString:@"-----BEGIN CERTIFICATE-----" withString:@""];
    str = [str stringByReplacingOccurrencesOfString:@"-----END CERTIFICATE-----" withString:@""];
    
    NSData *data2 = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    
    SecCertificateRef cert = SecCertificateCreateWithData(NULL , (__bridge CFDataRef ) data2);
    SecKeyRef key = SecCertificateCopyKey(cert);
    
    
    
    GTASN1Parser *p = [[GTASN1Parser alloc] initWithData:data1];
    BOOL issha1 = [p isSha1Sign];
    
    BOOL r = gtVerifySignature([p orginData], [p signData], key,issha1);
    
    CFRelease(key);
    GTLog(@"%d",r);
    
    [p test];
    
    GTLog(@"%@",[p getPublicKeyRawDataSha1]);
    
    return r;
    
    
    
}

void test1(){
    {
        NSString *str =  [[NSString alloc] initWithContentsOfFile:@"/Users/liw003/Downloads/test.pem" encoding:NSUTF8StringEncoding error:nil];
        str = [str stringByReplacingOccurrencesOfString:@"-----BEGIN CERTIFICATE-----" withString:@""];
        str = [str stringByReplacingOccurrencesOfString:@"-----END CERTIFICATE-----" withString:@""];
        
        NSData *dataCertificate = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
        
        GTASN1Parser *gp = [[GTASN1Parser alloc] initWithData:dataCertificate];
        [gp test];
        size_t hashBytesSize = CC_SHA1_DIGEST_LENGTH;
        uint8_t* hashBytes = malloc(hashBytesSize);
        NSData *certData = gp.orginData;
        CC_SHA1([certData bytes], (CC_LONG)[certData length], hashBytes);
        NSMutableString *strSha1 = [NSMutableString new];
        for (int i = 0 ; i < hashBytesSize; ++i ) {
            [strSha1  appendFormat:@"%x",hashBytes[i]];
        }
        GTLog(@"%@",strSha1);
        
        
//
        
        GTLog(@" isCA %d",[gp isCA]);
        GTLog(@"rsscc.com %d",[gp hasnDomain:@"rsscc.com"]);
        GTLog(@"tmall.com %d",[gp hasnDomain:@"tmall.com"]);
    }
}

#ifdef DEBUG
__attribute__((constructor)) static void PP(){
    GTLog(@"123");
//    test2();
    

//    NSData *signData = [p1 signData];
//    SecCertificateRef cert = SecCertificateCreateWithData(NULL , (__bridge CFDataRef ) dataRootCa);
//    SecKeyRef key = SecCertificateCopyKey(cert);
//    BOOL issha1 = [p1 isSha1Sign];
//
//    BOOL r = gtVerifySignature(data1, signData, key,issha1);
//    [p1 test];
//    GTLog(@"%d",r);
    

}
#endif
