//! Simple IPv6/v4 neighbor discovery tool.

use clap::Parser;

use std::net::ToSocketAddrs;

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// Network interface name
    #[arg(short, long)]
    interface: String,

    /// IPv6/IPv4 address or host name
    host: String,
}

fn main() {
    let args = Args::parse();
    println!("{:?}", args);

    let target_addr = (args.host + ":0").to_socket_addrs().unwrap().next().unwrap().ip();
    println!("{:?}", target_addr);
}