use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        let manifest =
            new_manifest("Posy.Trampoline").remove_dependency("Microsoft.Windows.Common-Controls");
        embed_manifest(manifest).expect("unable to embed manifest");
        println!("cargo:rerun-if-changed=build.rs");
    }
}
