// Brand the .app using the original transparent artwork. macOS may
// synthesize a rounded tile for an ordinary legacy ICNS; a custom file icon
// preserves its silhouette in Finder and in the Dock before the app launches.
import AppKit
import Foundation

guard CommandLine.arguments.count == 3 else {
    fputs("Usage: set-macos-app-icon.swift APP_PATH ICON_PATH\n", stderr)
    exit(1)
}
let appPath = CommandLine.arguments[1]
let iconPath = CommandLine.arguments[2]
guard appPath.hasSuffix(".app"),
      Bundle(path: appPath)?.bundleIdentifier == "org.evidenceforge.studio",
      let image = NSImage(contentsOfFile: iconPath) else {
    fputs("An EvidenceForge Studio .app and a readable icon are required.\n", stderr)
    exit(1)
}
guard NSWorkspace.shared.setIcon(image, forFile: appPath, options: []) else {
    fputs("Could not apply the Studio .app icon.\n", stderr)
    exit(1)
}
print("Applied transparent Studio .app icon.")
