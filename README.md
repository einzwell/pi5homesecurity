# Pi 5 Home Security

## Prerequisites

### Hardware Requirements

- Raspberry Pi 5, 8 GB RAM variant ([link](https://www.raspberrypi.com/products/raspberry-pi-5/))
- Raspberry Pi M.2 HAT+ ([link](https://www.raspberrypi.com/products/m2-hat-plus/))
- M.2 NVMe SSD
    - 256 GB (Samsung PM991) is used for this project, but 64 GB should be sufficient
- WiFi-capable IoT devices; for this project:
    - Bardi IDR-IPC-STC
    - Xiaomi MiTV-MOSR1

> [!WARNING]
> SSD (and M.2 HAT+) are not strictly required. However, read/write operations incurred by Suricata and Elasticsearch are very heavy and will quickly tear down your SD card.
> For this reason, I highly recommend **migrating your installation from SD card to SSD.**

### Software Requirements

- OS: Raspberry Pi OS Lite 64-bit
- Firewall: nftables
- IDS: Suricata
- Log ingestion: Elasticsearch & Kibana

View the [Setup](#setup) section for more details.

### Network Topology

The RPi 5 is bridged to a router/modem (in this case, Telkomsel Orbit Star Z2) and acts as the WiFi access point/hotspot to several client devices:

- Bardi IDR-IPC-STC (IP camera)
- Xiaomi MiTV-MOSR1 (smart TV)
- Ubuntu VM, running on KVM with a dedciated network interface via USB passthrough

All IP addresses are obtained via MAC-based DHCP (a la Dnsmasq), which makes them stable even if their leases expire.

![Network topology diagram](images/NetworkDiagram.png)

## Setup

### Migrating to SSD

> [!NOTE]
> Skip this section if you insist on running your installation on SD card.

- Ensure that your SSD is attached and take note of the block name (it should be something like `nvmeXnY`:

  ```
  $ lsblk
  NAME        MAJ:MIN RM   SIZE RO TYPE MOUNTPOINTS
  mmcblk0     179:0    0 232.2G  0 disk
  ├─mmcblk0p1 179:1    0   512M  0 part /boot/firmware
  └─mmcblk0p2 179:2    0 231.7G  0 part /
  nvme0n1     259:0    0 238.5G  0 disk
  ├─nvme0n1p1 259:1    0   512M  0 part
  └─nvme0n1p2 259:2    0   238G  0 part
  ```

- Clone your existing installation to SSD using [`rpi-cloner`](https://github.com/geerlingguy/rpi-clone) and follow the given instructions:

  ```
  curl https://raw.githubusercontent.com/geerlingguy/rpi-clone/master/install | sudo bash
  sudo rpi-clone nvme0n1
  ```

- Append the following to `/boot/firmware/config.txt` in order to enable the PCIe port:

  ```
  dtparam=nvme

  # You can also upgrade the PCIe lane speed to Gen 3 by adding this parameter (this is experimental)
  #dtparam=pciex1_gen=3
  ```

- Modify the boot order so that the NVMe drive gets checked first:

  ```
  sudo rpi-eeprom-config --edit
  ```

  Then modify the `BOOT_ORDER`
  ```
  BOOT_ORDER-0xf416
  ```
  The `6` at the end tells the ROM to attempt NVMe boot first. Check the [documentation](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#BOOT_ORDER) for more details. Reboot your RPi for the changes to take effect.

### WiFi AP

Run the following commands to create a WiFi access point bridged with your modem/router via Ethernet (adjust `$SSID` and `$PASSWORD`):

```
sudo nmcli device wifi Hotspot ssid $SSID password $PASSWORD ifname wlan0  # Can use names other than 'Hotspot'
sudo nmcli connection modify Hotspot ipv4.method disabled ipv6.method disabled  # don't assign any IP address since this will be bridged
sudo nmcli connection up Hotspot
```

Check the status of your WiFi AP by running `ip a` (it should be up without any IP address):

```
$ ip a
...
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast
state UP group default qlen 1000
 link/ether xx:xx:xx:xx:xx:xx brd ff:ff:ff:ff:ff:ff
```

### Suricata

#### Installation

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

#### Configuration

Open Suricata's configuration file (`/etc/suricata/suricata.yml`) and do the following:

> [!NOTE]
> Configuration and custom detection rule files are available at [`config/suricata/suricata.yml`](config/suricata/suricata.yaml) and [`config/suricata/local.rules`](config/suricata/local.rules), respectively.

- Modify `HOME_NET` to reflect your LAN subnet (in this case, 192.168.1.0/24)

  ```yaml
  HOME_NET: "[192.168.1.0/24]"
  ```

- Modify `HTTP_PORTS` to include both 80 and 443

  ```yaml
  HTTP_PORTS: "[80, 443]"
  ```

- Set up `AF_PACKET` mode

  ```yaml
  af-packet:
    - interface: eth0
      threads: auto
      cluster-id: 99
      cluster-type: cluster_flow
      defrag: no
      use-mmap: yes
      ring-size: 32768
      buffer-size: 64535
      copy-mode: tap
      copy-iface: wlan0
    - interface: wlan0
      threads: auto
      cluster-id: 90
      cluster-type: cluster_flow
      defrag: no
      use-mmap: yes
      ring-size: 32768
      buffer-size: 64535
      copy-mode: tap
      copy-iface: eth0
  ```

- Include `local.rules` in the `rule-files` section:

  ```yaml
  rule-files:
    suricata.rules
    local.rules
  ```

#### Integrate with Systemd Service

Run Suricata as a Systemd service by creating a service file at `/etc/systemd/suricata.service`:

> [!NOTE]
> The Systemd service file is available at [`config/suricata/suricata.service`](config/suricata/suricata.service).

```
[Unit]
Description=Suricata Intrusion Detection Service
After=syslog.target network-online.target

[Service]
ExecStart=/usr/bin/suricata -c /etc/suricata/suricata.yaml --af-packet
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill $MAINPID

[Install]
WantedBy=multi-user.target
```

#### Custom Rules & Threshold

These custom rules, defined at `/var/lib/suricata/rules/local.rules`, are mostly concerned with LAN activities. Threshold configuration (`/etc/suricata/threshold.config`) is defined to limit the alerts generated by volumetric (DoS) attacks. You may want to define your own custom rules and threshold configuration, depending on your network environment.

> [!NOTE]
> The custom rule and threshold files are available at [`config/suricata/local.rules`](config/suricata/local.rules) and [`config/suricata/threshold.config`](config/suricata/threshold.config)

```
alert tcp any any -> 192.168.1.181 any (msg:"[LOCAL] Bardi RTSP Access"; content:"RTSP/"; classtype:misc-activity; sid:9625001; rev:1;)
drop tcp any any -> 192.168.1.77 5555 (msg:"[LOCAL] Xiaomi MiTV ADB Access"; classtype:misc-activity; sid:9625002; rev:1;)
alert http any any -> 192.168.1.77 [8008, 8009, 8443] (msg:"[LOCAL] Xiaomi MiTV Chromecast Connection"; classtype:misc-activity; sid:962503; rev:1;)
alert tcp any !$HTTP_PORTS -> $HOME_NET any (msg:"[LOCAL] Potential TCP SYN Flood"; flags:S; classtype:attempted-dos; sid:962504; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"[LOCAL] Potential ICMP Flood"; itype:8; icode:0; classtype:attempted-dos; sid:962505; rev:1;)
alert udp any any -> $HOME_NET any (msg:"[LOCAL] Potential UDP Flood"; flow:not_established,to_server; flowbits:isnotset,udp_verify; flowbits:set,udp_verify; classtype:attempted-dos; sid:962506; rev:1;)
alert http any any -> 192.168.1.1 443 (msg:"[LOCAL] Router Control Panel Access"; classtype:misc-activity; sid:962507; rev:1;)
```

```
threshold gen_id 1, sig_id 962504, type both, track by_dst, count 150, seconds 300
threshold gen_id 1, sig_id 962505, type both, track by_dst, count 150, seconds 300
threshold gen_id 1, sig_id 962506, type both, track by_dst, count 250, seconds 300
```

### nftables

This nftables configuration serves to harden the RPi5. I originally intended to use nftables to block certain activites occuring between LAN devices, but it appears that nftables cannot act as an ARP proxy.

> [!NOTE]
> Nftables configuration is available at [`config/nftables/nftables.conf`](config/nftables/nftables.conf)

```
table ip filter {
	chain input {
		type filter hook input priority filter; policy drop;

		iif lo accept comment "Accept localhost traffic"
		fib daddr . iif type != { local, broadcast, multicast } drop comment "Drop packets whose destination is not configured on the incoming interface"
		ct state invalid drop comment "Drop invalid connections"
		ct state { established, related } accept comment "Accept traffic originating from this host"

		meta l4proto icmp icmp type echo-request limit rate over 10/second burst 5 packets drop comment "Block ICMP ping flood"
		meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn limit rate over 10/second burst 5 packets drop comment "Block TCP SYN flood"
		meta l4proto udp limit rate over 50/second burst 25 packets drop comment "Block UDP flood"

		meta l4proto icmp accept comment "Accept ICMP"
		tcp dport ssh accept comment "Accept SSH"
	}

	chain forward {
		type filter hook forward priority filter; policy drop; # Forwarding is handled by bridge
	}

	chain output {
		type filter hook output priority filter; policy accept; # Accept any outbound connection
	}
}
```

### Elasticsearch

###