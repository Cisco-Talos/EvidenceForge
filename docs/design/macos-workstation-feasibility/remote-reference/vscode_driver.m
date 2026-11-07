/* Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: MIT
 * One fresh Code instance, owned through its returned NSRunningApplication.
 * Private stdout is consumed by the runner. No PID-only signalling or pkill.
 */
#import <AppKit/AppKit.h>
#import <dispatch/dispatch.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef EFORGE_DOCKER_REFERENCE
#define REFERENCE_BUNDLE @"/Applications/Docker.app"
#define REFERENCE_DEADLINE 170
#define REFERENCE_STOP_LIMIT 30
#else
#define REFERENCE_BUNDLE @"/Applications/Visual Studio Code.app"
#define REFERENCE_DEADLINE 100
#define REFERENCE_STOP_LIMIT 7
#endif

static double monotonic(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
    return value.tv_sec + value.tv_nsec / 1000000000.0;
}

static void stop_loop(void) {
    [NSApp stop:nil];
    NSEvent *wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
        location:NSZeroPoint modifierFlags:0 timestamp:0 windowNumber:0 context:nil
        subtype:0 data1:0 data2:0];
    [NSApp postEvent:wake atStart:YES];
}

#ifdef EFORGE_DOCKER_REFERENCE
static NSArray<NSRunningApplication *> *docker_applications(NSDate *earliest) {
    NSArray<NSURL *> *bundles = @[
        [NSURL fileURLWithPath:@"/Applications/Docker.app"],
        [NSURL fileURLWithPath:@"/Applications/Docker.app/Contents/MacOS/Docker Desktop.app"]
    ];
    NSMutableArray<NSRunningApplication *> *matches = [NSMutableArray array];
    for (NSRunningApplication *candidate in [NSWorkspace sharedWorkspace].runningApplications) {
        if (candidate.terminated || !candidate.bundleURL || !candidate.executableURL) continue;
        if (earliest && (!candidate.launchDate || [candidate.launchDate compare:earliest] == NSOrderedAscending)) continue;
        for (NSURL *bundle in bundles) {
            NSURL *executable = [NSBundle bundleWithURL:bundle].executableURL;
            struct stat expected, actual, expectedImage, actualImage;
            if (executable && stat(bundle.path.fileSystemRepresentation, &expected) == 0 &&
                stat(candidate.bundleURL.path.fileSystemRepresentation, &actual) == 0 &&
                stat(executable.path.fileSystemRepresentation, &expectedImage) == 0 &&
                stat(candidate.executableURL.path.fileSystemRepresentation, &actualImage) == 0 &&
                expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino &&
                expectedImage.st_dev == actualImage.st_dev && expectedImage.st_ino == actualImage.st_ino) {
                [matches addObject:candidate]; break;
            }
        }
        if (matches.count > 16) return nil;
    }
    return matches;
}

static BOOL applications_ended(NSArray<NSRunningApplication *> *applications) {
    if (!applications.count) return NO;
    for (NSRunningApplication *application in applications) if (!application.terminated) return NO;
    return YES;
}
#endif

int main(int argc, char **argv) {
    @autoreleasepool {
        BOOL selftest = argc == 2 && strcmp(argv[1], "--loop-control") == 0;
        BOOL fileControl = argc == 3 && strcmp(argv[2], "--file-control") == 0;
#ifdef EFORGE_DOCKER_REFERENCE
        BOOL quitExisting = argc == 2 && strcmp(argv[1], "--quit-existing") == 0;
        BOOL startOnly = argc == 3 && strcmp(argv[2], "--start-only") == 0;
#else
        BOOL quitExisting = NO, startOnly = NO;
#endif
        if (getuid() == 0 || geteuid() != getuid()) return 2;
        if (!selftest && !quitExisting && ((argc != 2 && !fileControl && !startOnly) || argv[1][0] != '/')) return 2;
        alarm(selftest ? 5 : quitExisting ? 35 : REFERENCE_DEADLINE);
        struct stat root;
        if (!selftest && !quitExisting && (lstat(argv[1], &root) || !S_ISDIR(root.st_mode) || root.st_uid != getuid() ||
            (root.st_mode & 0777) != 0700)) return 2;
        @try {
            [NSApplication sharedApplication];
            [NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];
        } @catch (NSException *exception) {
            (void)exception;
            printf("{\"kind\":\"launch\",\"ok\":false,\"reason\":\"GUI_CONTEXT\"}\n");
            fflush(stdout); return 2;
        }
        __block BOOL queueServiced = NO;
        dispatch_async(dispatch_get_main_queue(), ^{ queueServiced = YES; });
        double start = monotonic();
        __block int outcome = 2;
        __block NSRunningApplication *application = nil;
#ifdef EFORGE_DOCKER_REFERENCE
        __block NSArray<NSRunningApplication *> *applicationGroup = nil;
#endif
        __block BOOL received = NO, reported = NO, matched = NO, forced = NO;
        __block double stopping = 0;
        __block const char *reason = "CALLBACK_TIMEOUT";
        NSURL *bundle = [NSURL fileURLWithPath:REFERENCE_BUNDLE];
        NSDate *requested = [NSDate date];
        NSString *stopPath = selftest ? nil : [[NSString stringWithUTF8String:argv[1]] stringByAppendingPathComponent:@"request-stop"];
        if (quitExisting) {
#ifdef EFORGE_DOCKER_REFERENCE
            applicationGroup = docker_applications(nil);
            application = applicationGroup.firstObject;
#endif
            received = YES; matched = application != nil;
            reason = matched ? "NONE" : "APPLICATION_IDENTITY";
        } else if (!selftest) {
            NSString *directory = [NSString stringWithUTF8String:argv[1]];
            NSWorkspaceOpenConfiguration *config = [NSWorkspaceOpenConfiguration configuration];
#ifdef EFORGE_DOCKER_REFERENCE
            config.createsNewApplicationInstance = NO;
            if (!startOnly) {
                config.environment = @{
                    @"EFORGE_REFERENCE_RUN": directory,
                    @"ZDOTDIR": [directory stringByAppendingPathComponent:@"shell"],
                    @"SHELL": @"/bin/zsh"
                };
            }
            config.arguments = @[];
#else
            config.createsNewApplicationInstance = YES;
            // Code can independently resolve a shell environment in more than
            // one component. Every zsh lookup must use our empty startup dir.
            config.environment = @{
                @"ZDOTDIR": [directory stringByAppendingPathComponent:@"shell"],
                @"SHELL": @"/bin/zsh",
                @"VSCODE_CLI": @"1"
            };
            config.arguments = @[
                [@"--user-data-dir=" stringByAppendingString:[directory stringByAppendingPathComponent:@"profile"]],
                [@"--extensions-dir=" stringByAppendingString:[directory stringByAppendingPathComponent:@"extensions"]],
                @"--skip-welcome", @"--skip-release-notes", @"--force-disable-user-env", @"--new-window",
                [directory stringByAppendingPathComponent:@"workspace"]
            ];
#endif
            config.activates = YES;
            [[NSWorkspace sharedWorkspace] openApplicationAtURL:bundle configuration:config
                completionHandler:^(NSRunningApplication *app, NSError *error) {
                  dispatch_async(dispatch_get_main_queue(), ^{
                    struct stat expected, actual;
                    BOOL same = app && app.bundleURL &&
                        stat(bundle.path.fileSystemRepresentation, &expected) == 0 &&
                        stat(app.bundleURL.path.fileSystemRepresentation, &actual) == 0 &&
                        expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino;
                    BOOL fresh = app.launchDate && [app.launchDate timeIntervalSinceDate:requested] >= -1.0;
                    if (same && fresh) application = app;
                    matched = same && fresh && !error;
                    reason = matched ? "NONE" : error ? "LAUNCH_ERROR" : "APPLICATION_IDENTITY";
                    if (error && [error.domain isEqualToString:NSOSStatusErrorDomain]) {
                        switch (error.code) {
                            case -10814: reason = "APP_NOT_FOUND"; break;
                            case -10827: reason = "NO_EXECUTABLE"; break;
                            case -10826: reason = "PERMISSION"; break;
                            case -10828: reason = "MULTIPLE_INSTANCES_PROHIBITED"; break;
                            case -10810: reason = "LAUNCH_FAILED"; break;
                            default: break;
                        }
                    }
                    received = YES;
                  });
                }];
        }
        NSTimer *timer = [NSTimer scheduledTimerWithTimeInterval:0.05 repeats:YES block:^(NSTimer *tick) {
            (void)tick;
            double now = monotonic();
            if (selftest) {
                if (queueServiced || now - start > 1) {
                    printf("{\"kind\":\"loop_control\",\"main_queue\":%s}\n", queueServiced ? "true" : "false");
                    fflush(stdout); outcome = queueServiced ? 0 : 2; stop_loop();
                }
                return;
            }
            if (!reported && (received || now - start > 10)) {
                printf("{\"kind\":\"launch\",\"ok\":%s,\"reason\":\"%s\",\"main_queue\":%s",
                       matched ? "true" : "false", reason, queueServiced ? "true" : "false");
                if (application) printf(",\"pid\":%d", application.processIdentifier);
                printf("}\n"); fflush(stdout); reported = YES;
                if (!application) { stop_loop(); return; }
                if (startOnly) { outcome = matched ? 0 : 2; stop_loop(); return; }
            }
            if (!reported || !application) return;
            struct pollfd input = {.fd=STDIN_FILENO, .events=POLLIN | POLLHUP};
            BOOL cancel = quitExisting ? NO : fileControl ? access(stopPath.fileSystemRepresentation, F_OK) == 0 :
                poll(&input, 1, 0) > 0 && input.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL);
#ifdef EFORGE_DOCKER_REFERENCE
            // Q asks this exact application object to quit normally. EOF or a
            // deadline only detaches; no Docker path force-stops the VM.
            if (!stopping && (quitExisting || (cancel && input.revents & POLLIN))) {
                char command = 0;
                if (quitExisting || read(STDIN_FILENO, &command, 1) == 1) {
                    if (quitExisting || command == 'Q') {
                        if (!quitExisting) applicationGroup = docker_applications([requested dateByAddingTimeInterval:-1]);
                        unsigned acceptedCount = 0;
                        for (NSRunningApplication *member in applicationGroup) {
                            if (!member.terminated && [member terminate]) acceptedCount++;
                        }
                        printf("{\"kind\":\"quit_request\",\"accepted\":%s,\"accepted_count\":%u,\"group_count\":%lu}\n",
                               acceptedCount ? "true" : "false", acceptedCount, (unsigned long)applicationGroup.count);
                        fflush(stdout); stopping = now; cancel = NO;
                    }
                }
            }
            if (cancel || now - start > REFERENCE_DEADLINE - 5) {
                printf("{\"kind\":\"detached\",\"terminated\":%s}\n", application.terminated ? "true" : "false");
                fflush(stdout); outcome = 0; stop_loop(); return;
            }
#else
            if (!application.terminated && !stopping && (cancel || !matched || now - start > 85)) {
                [application terminate]; stopping = now;
            }
            if (!application.terminated && stopping && now - stopping > 4 && !forced) {
                forced = YES; [application forceTerminate];
            }
#endif
#ifdef EFORGE_DOCKER_REFERENCE
            BOOL complete = stopping && applications_ended(applicationGroup);
#else
            BOOL complete = application.terminated;
#endif
            if (complete || (stopping && now - stopping > (quitExisting ? 28 : REFERENCE_STOP_LIMIT))) {
                printf("{\"kind\":\"ended\",\"terminated\":%s,\"forced\":%s}\n",
                       complete ? "true" : "false", forced ? "true" : "false");
                fflush(stdout); outcome = complete ? 0 : 2; stop_loop();
            }
        }];
        [NSApp run];
        [timer invalidate];
        return outcome;
    }
}
