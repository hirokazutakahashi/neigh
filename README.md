# neigh

Simple IPv6/v4 neighbor discovery tool for my Rust learning.

## Build and run

```bash
git clone https://github.com/hirokazutakahashi/neigh.git
cd neigh
cargo build --release
cd target/release
./neigh -h
```

## Using

### IPv4 ARP

Automatic selection of network interfaces.
```bash
./neigh 192.0.2.1
```

Manually specify network interface.
```bash
./neigh -i en0 192.0.2.1
```

Can also be specified by host name.
```bash
./neigh gw4.example.org
```

### IPv6 NDP

Automatic selection of network interfaces.
```bash
./neigh 2001:db8::1
```

Manually specify network interface.
```bash
./neigh -i en0 2001:db8::1
```

Can also be specified by host name.
```bash
./neigh gw6.example.org
```
