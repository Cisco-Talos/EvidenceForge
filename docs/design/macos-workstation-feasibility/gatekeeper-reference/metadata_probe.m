/* HUMAN ONLY. Fixed quarantine-presence/readiness diagnostics; never print values. */
#import <Foundation/Foundation.h>
#include <os/log.h>
#include <stdio.h>
#include <string.h>

int main(int argc, const char **argv) {
    @autoreleasepool {
        if (argc != 3) return 2;
        if (strcmp(argv[1], "ready") == 0) {
            os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "%{public}s", argv[2]);
            return 0;
        }
        if (strcmp(argv[1], "quarantine") != 0) return 2;
        NSString *path = [NSString stringWithUTF8String:argv[2]];
        if (path == nil || ![path isAbsolutePath]) return 2;
        NSURL *url = [NSURL fileURLWithPath:path];
        id value = nil;
        NSError *error = nil;
        if (![url getResourceValue:&value forKey:NSURLQuarantinePropertiesKey error:&error]) {
            puts("INCONCLUSIVE");
            return 2;
        }
        if (value != nil && ![value isKindOfClass:[NSDictionary class]]) {
            puts("INCONCLUSIVE");
            return 2;
        }
        puts(value == nil ? "ABSENT" : "PRESENT");
        return 0;
    }
}
