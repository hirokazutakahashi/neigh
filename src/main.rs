//! Simple IPv6/v4 neighbor discovery tool.

use clap::Parser;

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Network interface name
    #[arg(short, long)]
    interface: String,

    /// Host name or IPv6/IPv4 address
    host: String,
}

fn main() {
    let args = Args::parse();

    println!("{:?}", args);
}