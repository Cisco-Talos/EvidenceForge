use objc2::{AllocAnyThread, MainThreadMarker};
use objc2_app_kit::{NSApplication, NSImage};
use objc2_foundation::NSData;

pub fn set_dock_icon() -> Result<(), std::io::Error> {
    let main_thread = MainThreadMarker::new()
        .ok_or_else(|| std::io::Error::other("The Dock icon must be set on the main thread"))?;
    let data = NSData::with_bytes(include_bytes!("../icons/icon.png"));
    let image = NSImage::initWithData(NSImage::alloc(), &data)
        .ok_or_else(|| std::io::Error::other("Could not read the Studio icon"))?;
    // Apply the original transparent artwork explicitly in bundled launches too.
    // Tauri only does this in development; macOS otherwise synthesizes a tile.
    // SAFETY: NSApplication is accessed on the main thread with a non-null image.
    unsafe { NSApplication::sharedApplication(main_thread).setApplicationIconImage(Some(&image)) };
    Ok(())
}
