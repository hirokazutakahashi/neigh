//! Simple IPv6/v4 neighbor discovery tool.

use std::net::{ToSocketAddrs, IpAddr, Ipv4Addr, Ipv6Addr};
use std::process;

use clap::Parser;

use pnet::util;
use pnet::datalink::{Channel, MacAddr, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv6::{MutableIpv6Packet};
use pnet::packet::icmpv6::{Icmpv6Types};
use pnet::packet::icmpv6::ndp::{MutableNeighborSolicitPacket, NeighborAdvertPacket, NdpOption, NdpOptionTypes};

const PACKETSZ_ETHERNET: usize = EthernetPacket::minimum_packet_size();
const PACKETSZ_ARP: usize = MutableArpPacket::minimum_packet_size();
const PACKETSZ_IPV6: usize = MutableIpv6Packet::minimum_packet_size();
const PACKETSZ_NS: usize = MutableNeighborSolicitPacket::minimum_packet_size();
const PACKETSZ_NA: usize = NeighborAdvertPacket::minimum_packet_size();
const PACKETSZ_SOURCELLADDR: usize = 8;

fn match_ipv4(ipn: Ipv4Network, ip: Ipv4Addr) -> bool {
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

fn match_ipv6(ipn: Ipv6Network, ip: Ipv6Addr) -> bool {
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

fn snmcastaddr(target_ip: Ipv6Addr) -> (Ipv6Addr, MacAddr) {
    let target_ip_octets = &target_ip.octets();
    return (Ipv6Addr::new(0xff02, 0, 0, 0, 0, 1, 0xff00u16 | target_ip_octets[13] as u16, (target_ip_octets[14] as u16) << 8 | target_ip_octets[15] as u16),
        MacAddr(0x33, 0x33, 0xff, target_ip_octets[13], target_ip_octets[14], target_ip_octets[15]));
}

fn neigh_ndp(interface: &NetworkInterface, target_ip: Ipv6Addr) -> Result<MacAddr, String> {
    let source_mac = interface.mac.ok_or("Network interface has no MAC address.")?;

    let mut source_ip: Option<Ipv6Addr> = None;
    for ipn in &interface.ips {
        match ipn {
            IpNetwork::V6(ipn) => {
                source_ip = Some(ipn.ip());
                if match_ipv6(*ipn, target_ip) {
                    break;
                }
            },
            _ => continue
        }
    }
    let source_ip = source_ip.ok_or("Interace not found.".to_owned())?;

    let (snmcastaddr_ipv6, snmcastaddr_mac) = snmcastaddr(target_ip);

    let mut ethernet_buffer = [0u8; PACKETSZ_ETHERNET + PACKETSZ_IPV6 + PACKETSZ_NS + PACKETSZ_SOURCELLADDR];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).ok_or("Can't allocate Ethernet packet.".to_owned())?;

    ethernet_packet.set_destination(snmcastaddr_mac);
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Ipv6);

    let mut ipv6_buffer = [0u8; PACKETSZ_IPV6 + PACKETSZ_NS + PACKETSZ_SOURCELLADDR];
    let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buffer).ok_or("Can't allocate IPv6 packet.".to_owned())?;

    ipv6_packet.set_version(6);
    ipv6_packet.set_payload_length((PACKETSZ_NS + PACKETSZ_SOURCELLADDR) as u16);
    ipv6_packet.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6_packet.set_hop_limit(0xff);
    ipv6_packet.set_source(source_ip);
    ipv6_packet.set_destination(snmcastaddr_ipv6);

    let mut ns_buffer = [0u8; PACKETSZ_NS + PACKETSZ_SOURCELLADDR];
    let mut ns_packet = MutableNeighborSolicitPacket::new(&mut ns_buffer).ok_or("Can't allocate ICMPv6 packet.".to_owned())?;

    ns_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    ns_packet.set_target_addr(target_ip);
    let slladdr_ndpopt = NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: source_mac.octets().to_vec()
    };
    ns_packet.set_options(&[slladdr_ndpopt]);
    ns_packet.set_checksum(util::ipv6_checksum(ns_packet.packet(), 1, &[], &ipv6_packet.get_source(), &ipv6_packet.get_destination(), IpNextHeaderProtocols::Icmpv6));

    ipv6_packet.set_payload(ns_packet.packet_mut());
    ethernet_packet.set_payload(ipv6_packet.packet_mut());

    let (mut sender, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {return Err("Unknown channel type.".to_owned());},
        Err(e) => {return Err(e.to_string());}
    };

    match sender.send_to(ethernet_packet.packet(), None) {
        Some(result) => result.map_err(|err| err.to_string())?,
        None => {return Err("Can't send packet.".to_string());}
    }

    loop {
        let buf = receiver.next().map_err(|err| err.to_string())?;
        if buf.len() >= PACKETSZ_ETHERNET + PACKETSZ_IPV6 + PACKETSZ_NA {
            let ethernet_packet = EthernetPacket::new(&buf).ok_or("Can't allocate Ethernet packet.".to_owned())?;
            let na_packet = NeighborAdvertPacket::new(&buf[54..]).ok_or("Can't allocate ICMPv6 packet.".to_owned())?;
            if na_packet.get_icmpv6_type() == Icmpv6Types::NeighborAdvert && na_packet.get_target_addr() == target_ip {
                for ndp_option in na_packet.get_options_iter() {
                    if ndp_option.get_option_type() == NdpOptionTypes::TargetLLAddr {
                        let p = ndp_option.packet();
                        return Ok(MacAddr(p[2], p[3], p[4], p[5], p[6], p[7]));
                    }
                }
                return Ok(ethernet_packet.get_source());
            }
        }
    }
    // unreachable
}

fn neigh_arp(interface: &NetworkInterface, target_ip: Ipv4Addr) -> Result<MacAddr, String> {
    let source_mac = interface.mac.ok_or("Network interface has no MAC address.")?;

    let mut source_ip: Option<Ipv4Addr> = None;
    for ipn in &interface.ips {
        match ipn {
            IpNetwork::V4(ipn) => {
                source_ip = Some(ipn.ip());
                if match_ipv4(*ipn, target_ip) {
                    break;
                }
            },
            _ => continue
        }
    }
    let source_ip = source_ip.ok_or("Interace not found.".to_owned())?;

    let mut ethernet_buffer = [0u8; PACKETSZ_ETHERNET + PACKETSZ_ARP];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).ok_or("Can't allocate Ethernet packet.".to_owned())?;

    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(source_mac);
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; PACKETSZ_ARP];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).ok_or("Can't allocate ARP packet.".to_owned())?;

    arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(source_mac);
    arp_packet.set_sender_proto_addr(source_ip);
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_target_proto_addr(target_ip);

    ethernet_packet.set_payload(arp_packet.packet_mut());

    let (mut sender, mut receiver) = match pnet::datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {return Err("Unknown channel type.".to_owned());},
        Err(e) => {return Err(e.to_string());}
    };

    match sender.send_to(ethernet_packet.packet(), None) {
        Some(result) => result.map_err(|err| err.to_string())?,
        None => {return Err("Can't send packet.".to_string());}
    }

    loop {
        let buf = receiver.next().unwrap();
        let arp = ArpPacket::new(&buf[MutableEthernetPacket::minimum_packet_size()..]).ok_or("Can't allocate ARP packet.".to_owned())?;
        if arp.get_sender_proto_addr() == target_ip
            && arp.get_target_hw_addr() == source_mac
        {
            return Ok(arp.get_sender_hw_addr());
        }
    }
    // unreachable
}

fn find_interface_ipv4(interfaces: &Vec<NetworkInterface>, target_ip: Ipv4Addr) -> Result<&NetworkInterface, String> {
    for interface in interfaces {
        for ipn in &interface.ips {
            match ipn {
                IpNetwork::V4(ipn) => {
                    if match_ipv4(*ipn, target_ip) {
                        return Ok(interface);
                    }
                }
                _ => continue
            }
        }
    }
    Err("Interface not found.".to_owned())
}

fn find_interface_ipv6(interfaces: &Vec<NetworkInterface>, target_ip: Ipv6Addr) -> Result<&NetworkInterface, String> {
    for interface in interfaces {
        for ipn in &interface.ips {
            match ipn {
                IpNetwork::V6(ipn) => {
                    if match_ipv6(*ipn, target_ip) {
                        return Ok(interface);
                    }
                }
                _ => continue
            }
        }
    }
    Err("Interface not found.".to_owned())
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

    let mut target_ips = match (args.host + ":0").to_socket_addrs() {
        Ok(sockaddrs) => sockaddrs,
        _ => {eprintln!("{}", "Can't convert to IP address."); process::exit(1);}
    };
    let target_ip = match target_ips.next() {
        Some(ip) => ip.ip(),
        None => {eprintln!("{}", "Can't convert to IP address."); process::exit(1);}
    };

    let interfaces = pnet::datalink::interfaces();
    let interface = match args.interface {
        Some(interface_name) => interfaces.iter()
            .find(|interface| interface.name == interface_name)
            .unwrap(),
        None => match target_ip {
            IpAddr::V4(ip) => match find_interface_ipv4(&interfaces, ip) {
                Ok(interface) => interface,
                Err(msg) => {eprintln!("{}", msg); process::exit(1);}
            },
            IpAddr::V6(ip) => match find_interface_ipv6(&interfaces, ip) {
                Ok(interface) => interface,
                Err(msg) => {eprintln!("{}", msg); process::exit(1);}
            }
        }
    };

    match target_ip {
        IpAddr::V4(ip) => {
            match neigh_arp(&interface, ip) {
                Ok(target_mac) => {println!("{}", target_mac);},
                Err(msg) => {eprintln!("{}", msg);}
            }
        },
        IpAddr::V6(ip) => {
            match neigh_ndp(&interface, ip) {
                Ok(target_mac) => {println!("{}", target_mac);},
                Err(msg) => {eprintln!("{}", msg);}
            }
        }
    }
}