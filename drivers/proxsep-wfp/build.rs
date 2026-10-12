use std::{env, path::PathBuf};
use wdk_build::BuilderExt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    wdk_build::configure_wdk_binary_build()?;
    let config = wdk_build::Config::from_env_auto()?;
    let bindings = bindgen::Builder::wdk_default(config)?
        .header("wrapper.h")
        .default_enum_style(bindgen::EnumVariation::Consts)
        .derive_default(false)
        .layout_tests(false)
        .allowlist_function("(Io|Iof|Ke|Ex|Ps|Rtl|Fwpm|Fwps|Wdm).*" )
        .allowlist_type("(DRIVER_OBJECT|DEVICE_OBJECT|IRP|IO_STACK_LOCATION|UNICODE_STRING|EX_RUNDOWN_REF|KSPIN_LOCK|KIRQL|GUID|FWPS_.*|FWPM_.*|FWP_.*|SOCKADDR_STORAGE)")
        .allowlist_var("(IRP_MJ_.*|STATUS_.*|FILE_DEVICE_.*|FILE_.*|DO_.*|FWP.*|POOL_FLAG_.*)")
        .generate()?;
    bindings.write_to_file(PathBuf::from(env::var("OUT_DIR")?).join("wdk.rs"))?;
    println!("cargo:rustc-link-lib=Fwpkclnt");
    println!("cargo:rustc-link-lib=Wdmsec");
    println!("cargo:rerun-if-changed=wrapper.h");
    Ok(())
}
