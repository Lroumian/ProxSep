mod ui;

fn main() -> eframe::Result {
    let path = std::env::args_os().nth(1).map(std::path::PathBuf::from);
    eframe::run_native(
        proxsep_core::PRODUCT_NAME,
        eframe::NativeOptions {
            renderer: eframe::Renderer::Wgpu,
            viewport: eframe::egui::ViewportBuilder::default().with_inner_size([1100.0, 760.0]),
            ..Default::default()
        },
        Box::new(move |cc| Ok(Box::new(ui::DesktopApp::new(cc, path)))),
    )
}
