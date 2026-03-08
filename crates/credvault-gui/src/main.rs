// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            commands::discover_sources,
            commands::list_credentials,
            commands::extract_credentials,
            commands::export_bundle,
            commands::read_bundle,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CredVault");
}
