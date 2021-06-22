//
//  AppDelegate.m
//  AppAccessControl
//
//  Created by devin on 2021/6/22.
//  Copyright © 2021 devin. All rights reserved.
//

#import "AppDelegate.h"
#import "AccessControlUtil.h"

@interface AppDelegate ()

@property (weak) IBOutlet NSWindow *window;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    [AccessControlUtil addCurrentAppToKeychainItemWithCertName:@"xxx"];
}


- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
}


@end
