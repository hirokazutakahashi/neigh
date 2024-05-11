//! Simple IPv6/v4 neighbor discovery tool.

use std::net::ToSocketAddrs;
use std::net::{IpAddr, Ipv4Addr};

use clap::Parser;

use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::{MutablePacket, Packet};

fn neigh_arp(interface: NetworkInterface, target_ip: Ipv4Addr) -> MacAddr {
    let source_ip = match interface.ips.iter().find(|ip| ip.is_ipv4()).unwrap().ip() {
        IpAddr::V4(ip) => ip,
        _ => unreachable!(),
    };

    let (mut sender, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(interface.mac.unwrap());
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();

    dbg!("Sent ARP request");

    loop {
        let buf = receiver.next().unwrap();
        let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).unwrap();
        if arp.get_sender_proto_addr() == target_ip
            && arp.get_target_hw_addr() == interface.mac.unwrap()
        {
            dbg!("Received reply");
            return arp.get_sender_hw_addr();
        }
    }
    // unreachable
}

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct CmdArgs {
    /// Network interface name
    #[arg(short, long)]
    interface: String,

    /// IPv6/IPv4 address or host name
    host: String,
}

fn main() {
    let args = CmdArgs::parse();
    dbg!(&args);

    let target_ip = (args.host + ":0").to_socket_addrs().unwrap().next().unwrap().ip();
    dbg!(target_ip);

    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == args.interface)
        .unwrap();

    match target_ip {
        IpAddr::V4(ip) => {
            let target_mac = neigh_arp(interface, ip);
            dbg!(target_mac);
        },
        IpAddr::V6(ip) => {
            dbg!(ip);
        }
    }
}