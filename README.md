# Pi 5 Home Security

This README serves as a brief documentation of my thesis project regarding Raspberry Pi 5 as a home network security device.

## Network Topology

The Raspberry Pi 5 is bridged to a router/modem (in this case, the Telkomsel Orbit Star Z2) and acts as the Wi-Fi access point/hotspot to three client devices:

- Bardi IDR-IPC-STC (IP camera)
- Xiaomi MiTV-MOSR1 (smart TV)
- Ubuntu VM, running on KVM with a dedciated network interface (passthrough)

All IP addresses are obtained via MAC-based DHCP (a la Dnsmasq), which makes them stable even if their leases expire.



## Setup

### Wi-Fi AP

Run the following commands to create a Wi-Fi access point bridged with your modem/router via Ethernet (adjust `$SSID` and `$PASSWORD`):

```
sudo nmcli device wifi Hotspot ssid $SSID password $PASSWORD ifname wlan0  # Can use names other than 'Hotspot'
sudo nmcli connection modify Hotspot ipv4.method disabled ipv6.method disabled  # don't assign any IP address since this will be bridged
sudo nmcli connection up Hotspot
```

Check the status of your Wi-Fi AP by running `ip a` (it should be up without any IP address):

```
$ ip a
...
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast
state UP group default qlen 1000
 link/ether xx:xx:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff
```

### Suricata

Suricata is to be compiled from source and run with the AF_PACKET (layer 2) mode:

```
# Update
sudo apt-get update && sudo apt-get -y full-upgrade

# Install dependencies
sudo apt-get -y install wget libpcre2-dev build-essential autoconf
automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev pkgconfig zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 make libmagic-dev
libjansson-dev rustc cargo jq git-core install libnetfilter-queue-dev
libnetfilter-queue1 libnfnetlink-dev libnfnetlink0

# Download the source code
wget https://www.openinfosecfoundation.org/download/suricata-7.0.0.tar.gz
tar -xvzf suricata-7.0.0.tar.gz -C suricata
cd suricata

# Configure installation and compile
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make
sudo make install
sudo python ./suricata-update/setup.py build && sudo python ./suricataupdate/setup.py
sudo make install-full
sudo suricata-update
```

Now you need to modify 

### nftables

###

###