//! Simple IPv6/v4 neighbor discovery tool.

use clap::Parser;
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

use std::net::{ToSocketAddrs, IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::util;
use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv6::{MutableIpv6Packet};
use pnet::packet::icmpv6::{Icmpv6Types};
use pnet::packet::icmpv6::ndp::{MutableNeighborSolicitPacket, NeighborAdvertPacket, NdpOptionTypes};

fn neigh_ndp(interface: &NetworkInterface, target_ip: Ipv6Addr) -> MacAddr {
    let source_ip = match interface.ips.iter().find(|ip| ip.is_ipv6()).unwrap().ip() {
        IpAddr::V6(ip) => ip,
        _ => unreachable!(),
    };
    dbg!(source_ip);

    let (mut sender, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut ethernet_buffer = [0u8; 14+40+24]; // Ethernet 14 + IPv6 40 + NS 24
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    ethernet_packet.set_destination(MacAddr::broadcast()); // Shoud be Multicast.
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Ipv6);

    let mut ipv6_buffer = [0u8; 40+24]; // Any macro for packet size?
    let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer).unwrap();

    ipv6_packet.set_version(6);
    ipv6_packet.set_payload_length(24);
    ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6_packet.set_hop_limit(0xff);
    ipv6_packet.set_source(source_ip);
    ipv6_packet.set_destination(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)); //Shoud be Solicited-node multicast address.

    let mut ns_buffer = [0u8; 24]; // Any macro for packet size?
    let mut ns_packet = MutableNeighborSolicitPacket::new(&mut ns_buffer).unwrap();

    ns_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    ns_packet.set_target_addr(target_ip);
    ns_packet.set_checksum(util::ipv6_checksum(ns_packet.packet(), 1, &[], &ipv6_packet.get_source(), &ipv6_packet.get_destination(), IpNextHeaderProtocols::Icmpv6));

    ipv6_packet.set_payload(ns_packet.packet_mut());
    ethernet_packet.set_payload(ipv6_packet.packet_mut());

    sender
        .send_to(ethernet_packet.packet(), None)
        .unwrap()
        .unwrap();
    dbg!("Sent NS");

    loop {
        let buf = receiver.next().unwrap();
        if buf.len() >= 14 + 40 + 24 {
            let na_packet = NeighborAdvertPacket::new(&buf[54..]).unwrap();
            if na_packet.get_icmpv6_type() == Icmpv6Types::NeighborAdvert && na_packet.get_target_addr() == target_ip {
                for ndp_option in na_packet.get_options_iter() {
                    if ndp_option.get_option_type() == NdpOptionTypes::TargetLLAddr {
                        let r = ndp_option.packet();
                        return MacAddr(r[2], r[3], r[4], r[5], r[6], r[7]);
                    }
                }
            }
        }
    }
    // unreachable
}

fn neigh_arp(interface: &NetworkInterface, target_ip: Ipv4Addr) -> MacAddr {
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

fn match_v4(ipn: &Ipv4Network, ip: Ipv4Addr) -> bool {
    let len = ipn.prefix() as usize / 8;
    let octets_ipn = &ipn.ip().octets();
    let octets_ip = &ip.octets();
    for i in 0..len {
        if octets_ipn[i] != octets_ip[i] {
            return false;
        }
    }
    if len == 4 {
        return true;
    }

    let bits = ipn.prefix() % 8;
    let mask = !((1u16 << (8 - bits)) - 1) as u8;
    if octets_ipn[len] & mask == octets_ip[len] & mask {
        return true;
    }
    false
}

fn find_interface_v4(interfaces: &Vec<NetworkInterface>, target_ip: Ipv4Addr) -> &NetworkInterface {
    for interface in interfaces {
        println!("{}", interface.name);
        for ipn in &interface.ips {
            match ipn {
                IpNetwork::V4(ipn) => {
                    println!("{}", ipn);
                    if match_v4(ipn, target_ip) {
                        return interface;
                    }
                }
                _ => continue
            }
        }
    }
    panic!("interface not found.");
}

fn match_v6(ipn: &Ipv6Network, ip: Ipv6Addr) -> bool {
    let len = ipn.prefix() as usize / 8;
    let octets_ipn = &ipn.ip().octets();
    let octets_ip = &ip.octets();
    for i in 0..len {
        if octets_ipn[i] != octets_ip[i] {
            return false;
        }
    }
    if len == 16 {
        return true;
    }

    let bits = ipn.prefix() % 8;
    let mask = !((1u16 << (8 - bits)) - 1) as u8;
    if octets_ipn[len] & mask == octets_ip[len] & mask {
        return true;
    }
    false
}

fn find_interface_v6(interfaces: &Vec<NetworkInterface>, target_ip: Ipv6Addr) -> &NetworkInterface {
    for interface in interfaces {
        println!("{}", interface.name);
        for ipn in &interface.ips {
            match ipn {
                IpNetwork::V6(ipn) => {
                    println!("{}", ipn);
                    if match_v6(ipn, target_ip) {
                        return interface;
                    }
                }
                _ => continue
            }
        }
    }
    panic!("interface not found.");
}

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct CmdArgs {
    /// Network interface name
    #[arg(short, long, required = false)]
    interface: Option<String>,

    /// IPv6/IPv4 address or host name
    host: String,
}

fn main() {
    let args = CmdArgs::parse();
    dbg!(&args);

    let target_ip = (args.host + ":0").to_socket_addrs().unwrap().next().unwrap().ip();
    dbg!(target_ip);

    let interfaces = pnet::datalink::interfaces();
    let interface = match args.interface {
        Some(interfacestr) => interfaces.into_iter().find(|iface| iface.name == interfacestr).unwrap(),
        None => match target_ip {
            IpAddr::V4(ip) => {
                let iiii = find_interface_v4(&interfaces, ip).clone();
                iiii
            },
            IpAddr::V6(ip) => {
                let iiii = find_interface_v6(&interfaces, ip).clone();
                iiii
            }
        }
    };
    match target_ip {
        IpAddr::V4(ip) => {
            let target_mac = neigh_arp(&interface, ip);
            println!("{}", target_mac);
        },
        IpAddr::V6(ip) => {
            let target_mac = neigh_ndp(&interface, ip);
            println!("{}", target_mac);
        }
    }
}