fn main() {
    // TUN needs Administrator in v1 (privileged service mode comes later, see docs/PLAN.md §6.1).
    let windows = tauri_build::WindowsAttributes::new().app_manifest(include_str!("app.manifest"));
    tauri_build::try_build(tauri_build::Attributes::new().windows_attributes(windows)).expect("tauri build script failed");
}
