// Brand the mounted installer volume or the local DMG file using Studio's artwork.
// The volume icon is stored inside the image; the file icon is Finder metadata.
import AppKit
import Foundation

guard CommandLine.arguments.count == 3 else {
    fputs("Usage: set-macos-dmg-icon.swift VOLUME_OR_DMG_PATH ICON_PATH\n", stderr)
    exit(1)
}
let targetPath = CommandLine.arguments[1]
let iconPath = CommandLine.arguments[2]
let targetURL = URL(fileURLWithPath: targetPath)
guard let values = try? targetURL.resourceValues(forKeys: [.isVolumeKey, .isRegularFileKey]),
      values.isVolume == true || (values.isRegularFile == true && targetPath.hasSuffix(".dmg")),
      let image = NSImage(contentsOfFile: iconPath) else {
    fputs("A mounted volume or DMG file and a readable icon are required.\n", stderr)
    exit(1)
}
guard NSWorkspace.shared.setIcon(image, forFile: targetPath, options: []) else {
    fputs("Could not apply the Studio installer icon.\n", stderr)
    exit(1)
}
print("Applied Studio installer icon: \(targetPath)")
