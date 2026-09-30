//! Refusal executable installed under interpreter/tool aliases in a private
//! PATH directory for Rust-only agent rounds. Never examines or echoes user
//! arguments, stdin, credentials, or environment.

fn main() {
    eprintln!(
        "Rust-only task: Python execution is blocked. Use Cargo, Rust, or native agent-bus commands. No interpreter was started."
    );
    std::process::exit(126);
}
