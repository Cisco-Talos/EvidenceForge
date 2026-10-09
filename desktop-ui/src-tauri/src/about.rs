use tauri::{LogicalPosition, LogicalRect, LogicalSize, Manager, PhysicalRect};

pub fn show(app: &tauri::AppHandle) -> tauri::Result<()> {
    let main = app.get_webview_window("main");
    let window = if let Some(window) = app.get_webview_window("about") {
        window
    } else {
        let mut builder = tauri::WebviewWindowBuilder::new(
            app,
            "about",
            tauri::WebviewUrl::App("index.html#about".into()),
        )
        .title("About EvidenceForge Studio")
        .inner_size(380.0, 450.0)
        .resizable(false)
        .maximizable(false)
        .minimizable(false)
        .skip_taskbar(true)
        .visible(false);
        if let Some(main) = main.as_ref() {
            builder = builder.parent(main)?;
        }
        builder.build()?
    };
    if let Some(main) = main.as_ref() {
        center_over_parent(&window, main)?;
    } else {
        window.center()?;
    }
    // Position before showing, including the first opening from the macOS menu.
    window.show()?;
    window.set_focus()
}

fn center_over_parent(
    window: &tauri::WebviewWindow,
    parent: &tauri::WebviewWindow,
) -> tauri::Result<()> {
    let parent_bounds = PhysicalRect {
        position: parent.outer_position()?,
        size: parent.outer_size()?,
    };
    let window_size = window.outer_size()?;
    let monitor = parent.current_monitor()?;

    // macOS desktop positions share logical points. Each window's physical pixels
    // use its own display's scale, which can differ before About moves to its parent.
    // Other platforms share physical desktop coordinates.
    let parent_scale = if cfg!(target_os = "macos") {
        parent.scale_factor()?
    } else {
        1.0
    };
    let window_scale = if cfg!(target_os = "macos") {
        window.scale_factor()?
    } else {
        1.0
    };
    let work_area = monitor.map(|monitor| {
        let scale = if cfg!(target_os = "macos") {
            monitor.scale_factor()
        } else {
            1.0
        };
        logical_bounds(*monitor.work_area(), scale)
    });
    let position = centered_position(
        logical_bounds(parent_bounds, parent_scale),
        window_size.to_logical(window_scale),
        work_area,
    );
    if cfg!(target_os = "macos") {
        window.set_position(position)
    } else {
        window.set_position(position.to_physical::<i32>(1.0))
    }
}

fn logical_bounds(bounds: PhysicalRect<i32, u32>, scale: f64) -> LogicalRect<f64, f64> {
    LogicalRect {
        position: bounds.position.to_logical(scale),
        size: bounds.size.to_logical(scale),
    }
}

fn centered_position(
    parent: LogicalRect<f64, f64>,
    window_size: LogicalSize<f64>,
    work_area: Option<LogicalRect<f64, f64>>,
) -> LogicalPosition<f64> {
    let mut position = LogicalPosition::new(
        parent.position.x + (parent.size.width - window_size.width) / 2.0,
        parent.position.y + (parent.size.height - window_size.height) / 2.0,
    );
    if let Some(area) = work_area {
        let max_x = area.position.x + (area.size.width - window_size.width).max(0.0);
        let max_y = area.position.y + (area.size.height - window_size.height).max(0.0);
        position.x = position.x.clamp(area.position.x, max_x);
        position.y = position.y.clamp(area.position.y, max_y);
    }
    position
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(x: f64, y: f64, width: f64, height: f64) -> LogicalRect<f64, f64> {
        LogicalRect {
            position: LogicalPosition::new(x, y),
            size: LogicalSize::new(width, height),
        }
    }

    #[test]
    fn centers_over_parent_instead_of_display() {
        assert_eq!(
            centered_position(
                bounds(300.0, 100.0, 1000.0, 700.0),
                LogicalSize::new(380.0, 478.0),
                Some(bounds(0.0, 25.0, 1920.0, 1015.0)),
            ),
            LogicalPosition::new(610.0, 211.0),
        );
    }

    #[test]
    fn centers_across_displays_with_different_scales_and_negative_origins() {
        let parent = PhysicalRect {
            position: (-2800, 200).into(),
            size: (2000, 1400).into(),
        };
        let monitor = PhysicalRect {
            position: (-3840, 50).into(),
            size: (3840, 2030).into(),
        };
        let dialog = tauri::PhysicalSize::new(380, 478);
        assert_eq!(
            centered_position(
                logical_bounds(parent, 2.0),
                dialog.to_logical(1.0),
                Some(logical_bounds(monitor, 2.0)),
            ),
            LogicalPosition::new(-1090.0, 211.0),
        );
    }

    #[test]
    fn keeps_dialog_within_work_area_when_parent_is_partly_offscreen() {
        for (parent, expected) in [
            (bounds(-1000.0, -500.0, 1000.0, 700.0), (100.0, 50.0)),
            (bounds(1900.0, 900.0, 1000.0, 700.0), (1520.0, 622.0)),
        ] {
            assert_eq!(
                centered_position(
                    parent,
                    LogicalSize::new(380.0, 478.0),
                    Some(bounds(100.0, 50.0, 1800.0, 1050.0)),
                ),
                LogicalPosition::from(expected),
            );
        }
    }

    #[test]
    fn tolerates_missing_monitor_and_work_area_smaller_than_dialog() {
        let parent = bounds(300.0, 100.0, 1000.0, 700.0);
        let dialog = LogicalSize::new(380.0, 478.0);
        assert_eq!(
            centered_position(parent, dialog, None),
            LogicalPosition::new(610.0, 211.0),
        );
        assert_eq!(
            centered_position(parent, dialog, Some(bounds(100.0, 50.0, 200.0, 200.0))),
            LogicalPosition::new(100.0, 50.0),
        );
    }
}
