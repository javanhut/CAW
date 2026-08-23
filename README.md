# CAW (Corvus Access Wifi )

# Description

CAW is a wifi terminal utility built in rust for raven linux.
It is an easy to use tool for connection to wireless networks without the difficult of other terminal tools.

# Quick Start

## Active a ethernet port

*(example port name eth0)

```bash
caw ports # List ports
caw port eth0 up # Active port and set it up
caw port info eth0 # Get all port information for eth0
caw port set eth0 dhcp # Sets ipv4/ipv6 with dhcp
caw port info eth0 --protocol # Gets ipv4 and ipv6 information
caw port info eth0 --mac # Get Mac Addresss information of port
```

## Scan for wireless networks

```bash
caw scan
```

## Connect to wireless network

```bash
caw connect ExampleNetworkName #runs an interactive setup for this network
```

## Disconnect from wireless network

```bash
caw disconnect ExampleNetworkName
```
