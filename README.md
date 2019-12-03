# Simple Router

## High level design

**router.cpp**: handles the incoming packets and does forwarding, ARP requesting, ARP request queuing, ARP entry insertion, and ICMP echo-replying

**arp-cache.cpp**: stores ARP entries and ARP requests, periodically removes ARP entries if stale, sends ARP requests for each request in its queue

**routing-table.cpp**: computes from its routing table entries the longest matching prefix for the next hop given an destination IP

## Setup and use

**Must have latest version of VirtualBox (6.0.x) installed and [Vagrant Tools](https://www.vagrantup.com/downloads.html)**

Boot VM and ssh in:
```
vagrant up
vagrant ssh
cd /vagrant
```

Run router, which supports a 2-server 1-client mininet topology (can be configured):
```
make
./router
```

Run mininet:
```
sudo ./run.py
```

Ping examples:
```
client ping server1
client ping server2
server1 ping server2
```

File transfer:
```
mininet> server1 /vagrant/server 5678 /vagrant/ &
mininet> client /vagrant/client server1 5678 /vagrant/SOME_FILE.file &
```
