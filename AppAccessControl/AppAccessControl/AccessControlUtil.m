//
//  AccessControlUtil.m
//  AppAccessControl
//
//  Created by devin on 2021/6/22.
//  Copyright © 2021 devin. All rights reserved.
//

#import "AccessControlUtil.h"

#import <Security/Security.h>


@implementation AccessControlUtil

// https://github.com/st3fan/osx-10.9/tree/34e34a6a539b5a822cda4074e56a7ced9b57da71/SecurityTool-55115
+ (void)addCurrentAppToKeychainItemWithCertName:(NSString *)name {
    
    CFStringRef cf_name = (__bridge CFStringRef)name;
    SecKeychainItemRef itemRef = nil;
//    SecKeychainAttribute attris[1];
//    attris->tag = kSecLabelItemAttr;
//    CFDataRef label = CFStringCreateExternalRepresentation(NULL,
//                                                           cf_empid,
//                                                           kCFStringEncodingUTF8,
//                                                           0);
//    attris->length = (UInt32)CFDataGetLength(label);
//    attris->data = (void *)CFDataGetBytePtr(label);
//
//    SecKeychainAttributeList attriList;
//    attriList.count = 1;
//    attriList.attr = attris;
//
//    SecKeychainSearchRef searchRef ;
//    OSStatus s = SecKeychainSearchCreateFromAttributes(NULL, kSecPrivateKeyItemClass, &attriList, &searchRef);
//    while (true) {
//        s = SecKeychainSearchCopyNext(searchRef, &itemRef);
//        if (itemRef == NULL) {
//            continue;
//        }
//        break;
//    }

//    SecKeychainRef keychain;
//    SecKeychainOpen("/Users/devin/Library/Keychains/login.keychain-db", &keychain);
//
//    CFMutableArrayRef mKeychains = CFArrayCreateMutable(NULL, 1, NULL);
//    if (keychain) {
//        CFArrayAppendValue(mKeychains, keychain);
//    }

    CFTypeRef result;
    NSDictionary* query = [NSDictionary dictionaryWithObjectsAndKeys:
                           (__bridge NSString *)kSecClassKey,kSecClass,
//                           mKeychains,kSecMatchSearchList,
                           cf_name,kSecAttrLabel,
                           kCFBooleanTrue,kSecReturnRef,nil];
    OSStatus s = SecItemCopyMatching((CFDictionaryRef)query, &result);
    if (s == noErr && CFGetTypeID(result) == SecKeyGetTypeID()) {
        SecKeyRef secKey = (SecKeyRef)result;
        itemRef = (SecKeychainItemRef)secKey;
    }
    if (itemRef) {
        CFMutableArrayRef mAppRef = CFArrayCreateMutable(CFAllocatorGetDefault(), 1, NULL);

        NSString *bundlePath = [[NSBundle mainBundle] bundlePath];
        SecTrustedApplicationRef trustAppRef = nil;
        SecTrustedApplicationCreateFromPath([bundlePath UTF8String], &trustAppRef);
        if (trustAppRef) {
            CFArraySetValueAtIndex(mAppRef, 0, trustAppRef);
        }
        
//        SecTrustedApplicationRef eapolApp = nil;
//        SecTrustedApplicationCreateFromPath("/System/Library/SystemConfiguration/EAPOLController.bundle/Contents/Resources/eapolclient", &eapolApp);
//        if (eapolApp) {
//            CFArraySetValueAtIndex(mAppRef, 1, eapolApp);
//        }

        SecAccessRef newAccess ;
        create_access("Configure Profile", NO, mAppRef, &newAccess);
        modify_access(itemRef, newAccess);
    }
    else {
        NSLog(@"SecKeychainItemRef is null");
    }
}


int
create_access(const char *accessName, Boolean allowAny, CFArrayRef trustedApps, SecAccessRef *access)
{
    int result = 0;
    CFArrayRef appList = NULL;
    CFArrayRef aclList = NULL;
    CFStringRef description = NULL;
    const char *descriptionLabel = (accessName) ? accessName : "<unlabeled key>";
    CFStringRef promptDescription = NULL;
//    CSSM_ACL_KEYCHAIN_PROMPT_SELECTOR promptSelector;
    SecKeychainPromptSelector promptSelector;
    SecACLRef aclRef;
    OSStatus status;

    if (accessName) {
        description = CFStringCreateWithCString(NULL, descriptionLabel, kCFStringEncodingUTF8);
    }

    status = SecAccessCreate(description, trustedApps, access);
    if (status)
    {
        NSLog(@"SecAccessCreate %d",status);
        result = 1;
        goto cleanup;
    }

    // get the access control list for decryption operations (this controls access to an item's data)
    aclList = SecAccessCopyMatchingACLList(*access, kSecACLAuthorizationDecrypt);
//    status = SecAccessCopySelectedACLList(*access, CSSM_ACL_AUTHORIZATION_DECRYPT, &aclList);
    if (aclList == nil)
    {
        NSLog(@"SecAccessCopyMatchingACLList error");

        result = 1;
        goto cleanup;
    }

    // get the first entry in the access control list
    aclRef = (SecACLRef)CFArrayGetValueAtIndex(aclList, 0);
//    status = SecACLCopySimpleContents(aclRef, &appList, &promptDescription, &promptSelector);
    status = SecACLCopyContents(aclRef, &appList, &promptDescription, &promptSelector);
    if (status)
    {
        NSLog(@"SecACLCopySimpleContents %d",status);

        result = 1;
        goto cleanup;
    }

    if (allowAny) // "allow all applications to access this item"
    {
        // change the decryption ACL to not require the passphrase, and have a nil application list.
//        promptSelector.flags &= ~CSSM_ACL_KEYCHAIN_PROMPT_REQUIRE_PASSPHRASE;
        promptSelector &= ~kSecKeychainPromptRequirePassphase;
//        status = SecACLSetSimpleContents(aclRef, NULL, promptDescription, &promptSelector);
        status = SecACLSetContents(aclRef, NULL, promptDescription, promptSelector);
        
    }
    else // "allow access by these applications"
    {
        // modify the application list
//        status = SecACLSetSimpleContents(aclRef, trustedApps, promptDescription, &promptSelector);
        status = SecACLSetContents(aclRef, trustedApps, promptDescription, promptSelector);
    }
    if (status)
    {
        NSLog(@"SecACLSetContents : %d", status);
        result = 1;
        goto cleanup;
    }

cleanup:
    if (description)
        CFRelease(description);
    if (promptDescription)
        CFRelease(promptDescription);
    if (appList)
        CFRelease(appList);
    if (aclList)
        CFRelease(aclList);

    return result;
}

// merge_access
//
// This function merges the contents of otherAccess into access.
// Simple ACL contents are assumed, and only the standard ACL
// for decryption operations is currently processed.
//
int
merge_access(SecAccessRef access, SecAccessRef otherAccess)
{
    OSStatus status = noErr;
    CFArrayRef aclList, newAclList;

    // get existing access control list for decryption operations (this controls access to an item's data)
//    status = SecAccessCopySelectedACLList(access, CSSM_ACL_AUTHORIZATION_DECRYPT, &aclList);
    
    aclList = SecAccessCopyMatchingACLList(access, kSecACLAuthorizationDecrypt);
    if (aclList == nil) {
        return errSecACLNotSimple;
    }
    // get desired access control list for decryption operations
//    status = SecAccessCopySelectedACLList(otherAccess, CSSM_ACL_AUTHORIZATION_DECRYPT, &newAclList);
    newAclList = SecAccessCopyMatchingACLList(otherAccess, kSecACLAuthorizationDecrypt);

    if (newAclList == nil) {
        newAclList = nil;
        status = errSecACLNotSimple;
    } else {
        SecACLRef aclRef=(SecACLRef)CFArrayGetValueAtIndex(aclList, 0);
        SecACLRef newAclRef=(SecACLRef)CFArrayGetValueAtIndex(newAclList, 0);
        CFArrayRef appList=nil;
        CFArrayRef newAppList=nil;
        CFMutableArrayRef mergedAppList = nil;
        CFStringRef promptDescription=nil;
        CFStringRef newPromptDescription=nil;
        SecKeychainPromptSelector promptSelector = kSecKeychainPromptRequirePassphase;
        SecKeychainPromptSelector newPromptSelector = kSecKeychainPromptRequirePassphase;

        status = SecACLCopyContents(aclRef, &appList, &promptDescription, &promptSelector);
        if (!status) {
            status = SecACLCopyContents(newAclRef, &newAppList, &newPromptDescription, &newPromptSelector);
        }
        if (!status) {
            if (appList) {
                mergedAppList = CFArrayCreateMutableCopy(NULL, 0, appList);
            }
            if (newAppList) {
                if (mergedAppList) {
                    // 排除重复添加进程
                    NSArray *tmp_appList = (__bridge  NSArray *)appList;
                    NSArray *tmp_newAppList = (__bridge  NSArray *)newAppList;
                    for (int i = 0; i < tmp_newAppList.count; i++) {
                        SecTrustedApplicationRef app = (__bridge SecTrustedApplicationRef)([tmp_newAppList objectAtIndex:i]);
                        CFDataRef dataRef ;
                        SecTrustedApplicationCopyData(app, &dataRef);
                        if (dataRef) {
                            NSString *path1 = [[NSString alloc] initWithData:(__bridge NSData *)dataRef encoding:NSUTF8StringEncoding];
                            BOOL isExist = NO;
                            for (int i = 0; i < tmp_appList.count; i++) {
                                SecTrustedApplicationRef app = (__bridge SecTrustedApplicationRef)([tmp_appList objectAtIndex:i]);
                                CFDataRef dataRef ;
                                SecTrustedApplicationCopyData(app, &dataRef);
                                if (dataRef) {
                                    NSString *path2 = [[NSString alloc] initWithData:(__bridge NSData *)dataRef encoding:NSUTF8StringEncoding];
                                    if ([path2 isEqualToString:path1]) {
                                        isExist = YES;
                                        break;
                                    }
                                }
                            }
                            if (!isExist) {
                                CFIndex count = CFArrayGetCount(mergedAppList);
                                CFArrayInsertValueAtIndex(mergedAppList, count, app);
                            }
                        }
                        else {
                            CFIndex count = CFArrayGetCount(mergedAppList);
                            CFArrayInsertValueAtIndex(mergedAppList, count, app);
                        }
                    }
                    
//                    CFArrayAppendArray(mergedAppList, newAppList, CFRangeMake(0, CFArrayGetCount(newAppList)));

                    
                } else {
                    mergedAppList = CFArrayCreateMutableCopy(NULL, 0, newAppList);
                }
            }
            promptSelector = newPromptSelector;
            status = SecACLSetContents(aclRef, mergedAppList, newPromptDescription, newPromptSelector);
//            status = SecACLSetContents(aclRef, mergedAppList, promptDescription, promptSelector);
        }

        if (appList) CFRelease(appList);
        if (newAppList) CFRelease(newAppList);
        if (mergedAppList) CFRelease(mergedAppList);
        if (promptDescription) CFRelease(promptDescription);
        if (newPromptDescription) CFRelease(newPromptDescription);
    }
    if (aclList) CFRelease(aclList);
    if (newAclList) CFRelease(newAclList);

    return status;
}

// modify_access
//
// This function updates the access for an existing item.
// The provided access is merged with the item's existing access.
//
int
modify_access(SecKeychainItemRef itemRef, SecAccessRef access)
{
    OSStatus status;
    SecAccessRef curAccess = NULL;
    // for historical reasons, we have to modify the item's existing access reference
    // (setting the item's access to a freshly created SecAccessRef instance doesn't behave as expected)
    status = SecKeychainItemCopyAccess(itemRef, &curAccess);
    if (status) {
        NSLog(@"SecKeychainItemCopyAccess %d",status);
    } else {
        status = merge_access(curAccess, access); // make changes to the existing access reference
        if (!status) {
            status = SecKeychainItemSetAccess(itemRef, curAccess); // will prompt!
            if (status) {
                NSLog(@"SecKeychainItemSetAccess %d",status);

            }
        }
    }
    if (curAccess) {
        CFRelease(curAccess);
    }
    return status;
}


@end
