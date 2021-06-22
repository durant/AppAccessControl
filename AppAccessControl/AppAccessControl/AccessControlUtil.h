//
//  AccessControlUtil.h
//  AppAccessControl
//
//  Created by devin on 2021/6/22.
//  Copyright © 2021 devin. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface AccessControlUtil : NSObject

+ (void)addCurrentAppToKeychainItemWithCertName:(NSString *)name;

@end

NS_ASSUME_NONNULL_END
