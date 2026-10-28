use serde_json::json;

fn help() {
    println!("HelloCar {} — Linux wireless HiCar receiver", env!("CARGO_PKG_VERSION"));
    println!("Usage: hellocar run --network-interface IFACE (--peer MAC | --pair SECONDS) [OPTIONS]");
    println!("  --identity PATH       Private persisted identity and fixed PIN");
    println!("  --auth-store PATH     Persistent native authentication key directory");
    println!("  --auth-library PATH   Native HiChain compatibility library");
    println!("  --live-socket PATH    Connect to a local media consumer (Unix socket)");
    println!("  --audio-binary PATH   Audio-only FFmpeg or a system FFmpeg executable");
    println!("  --adapter PATH        BlueZ adapter path (default /org/bluez/hci0)");
    println!("  --duration SECONDS    Stop after this duration; 0 runs until signalled");
    println!("Developer commands: codec, identity-check; private workers are launched internally.");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") || args[0] == "help" {
        help(); return;
    }
    if args == ["--version"] || args == ["version"] {
        println!("hellocar {}", env!("CARGO_PKG_VERSION")); return;
    }
    if let Err(error) = hellocar::hicar::run(&args) {
        println!("{}", json!({"event":"hicar_error","detail":error}));
        std::process::exit(1);
    }
}
