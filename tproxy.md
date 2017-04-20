                <meta charset="utf-8" emacsmode="-*- markdown -*-">
                            **Linux transparent proxy support**

DRAFT!

Introduction
===============================================================================
The Linux kernel contains facilities for performing transparent proxying.
In short this means that the operating system functions as a router, but
some (or all) traffic gets redirected for userspace processing.

This could be used for example to implement a transparent http proxy which
could then for example apply policy, scan for viruses etc. There are DNS
applications too.

While the kernel [does contain a
file](https://www.kernel.org/doc/Documentation/networking/tproxy.txt) that
describes this functionality, and this file is actually not wrong, it
certainly is confusing.  Other components required to really make
transparent proxying work are described on various [Stack
Exchange](http://stackoverflow.com/questions/5615579/how-to-get-original-destination-port-of-redirected-udp-message) pages. 
Other flags hang out in a
[number](http://man7.org/linux/man-pages/man7/ip.7.html)
[of](http://ipset.netfilter.org/iptables-extensions.man.html) manpages.

This document attempts to document everything in one place, with references
to the authoritative sources. Note that this documentation is quite at odds
with other explanations found online, but it is believed this page is
correct.

Some of the "pseudocode" examples actually compile when used with
[SimpleSockets](https://github.com/ahupowerdns/simplesocket). This is used
because these examples are easier to read than the somewhat cumbersome raw
BSD sockets API equivalent.


The routing part
================
When a packet enters a Linux system it is routed, dropped or if the
destination address matches a local address, accepted for processing by the
system itself. 

Local addresses can be specific, like 192.0.2.1, but can also match whole
ranges. This is for example how 127.0.0.0/8 is considered as 'local'.

It is entirely possible to tell Linux 0.0.0.0/0 ('everything') is local, but
this would make it unable to connect to any network.

However, with a separate routing table, we can enable this selectively:

```
iptables -t mangle -I PREROUTING -p udp --dport 5301 -j MARK --set-mark 1
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

This says: mark all UDP packets coming in to the system to port 5301 with
'1'.  The next two lines create and populate a routing table for packets
marked with '1', and subsequently declare that in that table the whole IPv4
range is "local".

Intercepting packets: the userspace part
----------------------------------------
With the routing rule and table above, the following simple code intercepts
all packets routed through the system destined for 5301, regardless of
destination IP address:

```
  Socket s(AF_INET, SOCK_DGRAM, 0);
  ComboAddress local("0.0.0.0", 5301);
  ComboAddress remote(local);

  SBind(s, local);

  for(;;) {
    string packet=SRecvfrom(s, 1500, remote);
    printf("Received a packet\n");
  }
```


Sending packets from non-local IP addresses
-------------------------------------------

Regular sockets are used for transparent proxying, but a special flag,
IP_TRANSPARENT, is set to indicate that this socket might receive data
destined for a non-local addresses.

Note: as explained above, we can declare 0.0.0.0/0 as "local" (or ::/0), but
if this is not in a default routing table, we still need this flag to
convince the kernel we know what we are doing.

The following code spoofs a UDP address from 1.2.3.4 to 198.41.0.4:

```
  Socket s(AF_INET, SOCK_DGRAM, 0);
  SSetsockopt(s, IPPROTO_IP, IP_TRANSPARENT, 1);
  ComboAddress local("1.2.3.4", 5300);
  ComboAddress remote("198.41.0.4", 53);
  
  SBind(s, local);
  SSendto(s, "hi!", remote);
```

Note: this requires root or CAP_NET_ADMIN to work. 

With tcpdump we can observe that an actual packet leaves the host:

```
tcpdump -n host 1.2.3.4
21:29:41.005856 IP 1.2.3.4.5300 > 198.41.0.4.53: [|domain]
```

IP_TRANSPARENT is mentioned in [ip(7)](http://man7.org/linux/man-pages/man7/ip.7.html).

 
The iptables part
-----------------
In the code examples above, traffic had to be delivered to a socket bound to
the exact port of the intercepted traffic. We also had to bind the socket to
0.0.0.0 (or ::) for it to see all traffic.

`iptables` has a target called TPROXY which gives us additional flexibility
to send intercepted traffic to a specific local IP address and
simultaneously mark it too.

The basic syntax is:

```
iptables -t mangle -A PREROUTING -p tcp --dport 25 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 10025 --on-ip 127.0.0.1
```

This says: take everything destined for a port 25 on TCP and deliver this
for a process listening on 127.0.0.1:10025 and mark the packet with 1.

This mark then makes sure the packet ends up in the right routing table.

With the `iptables` line above, we can now bind to 127.0.0.1:10025 and
receive all traffic destined for port 25. Note that the IP_TRANSPARENT
socket still needs to be set for this to work, even when we bind to
127.0.0.1.

Getting the original destination address
========================================
For TCP sockets, the original destination address and port of a socket is
available via `getsockname()`.  This is needed for example to setup a
connection to the originally intended destination.

An example piece of code:
```
  Socket s(AF_INET, SOCK_STREAM, 0);
  SSetsockopt(s, IPPROTO_IP, IP_TRANSPARENT, 1);
  ComboAddress local("127.0.0.1", 10025);

  SBind(s, local);
  SListen(s, 128);

  ComboAddress remote(local), orig(local);
  int client = SAccept(s, remote);
  cout&lt;&lt;"Got connection from "&lt;&lt;remote.toStringWithPort()&lt;&lt;endl;

  SGetsockname(client, orig);
  cout&lt;&lt;"Original destination: "&lt;&lt;orig.toStringWithPort()&lt;&lt;endl;
```


For UDP, the IP_RECVORIGDSTADDR socket option can be set with
`setsockopt()`. To actually get to that address, `recvmsg()` must be used
which will then pass the original destination as a cmsg with index
IP_ORIGDSTADDR containing a struct sockaddr_in.


Caveats
=======
None of this works locally. Packets need to actually enter your system and
be routed. 

In addition, the reverse path filter may confuse things by dropping packets. 
Finally, make sure that the Linux machine is actually setup to forward.
Combined:

```
sysctl net.ipv4.conf.all.rp_filter=0
sysctl net.ipv4.conf.all.forwarding=1
sysctl net.ipv6.conf.all.forwarding=1
```


The -m socket line you find everywhere
======================================
Many TPROXY iptables examples on the internet contain an unexplained
refinement that uses `-m socket -p tcp`. The `socket` module of iptables
matches patches that correspond to a local socket, which may be more precise
or faster than navigating a set of specific rules.

The setup you'll find everywhere sets up a redirect chain which marks and
accepts packets:

```
iptables -t mangle -N DIVERT
iptables -t mangle -A DIVERT -j MARK --set-mark 1
iptables -t mangle -A DIVERT -j ACCEPT
```

The following then makes sure that everything that corresponds to an
established local socket gets sent there, followed by what should happen to
new packets:

```
iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
iptables -t mangle -A PREROUTING -p tcp --dport 25 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 10025 --on-ip 127.0.0.1
iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 10080 --on-ip 127.0.0.1
```





<script>window.markdeepOptions={};
window.markdeepOptions.tocStyle="short";</script>
<!--  Markdeep:  --><style  class="fallback">body{visibility:hidden;white-space:pre;font-family:monospace}</style><script  src="markdeep.min.js"></script><script  src="https://casual-effects.com/markdeep/latest/markdeep.min.js"></script><script>window.alreadyProcessedMarkdeep||(document.body.style.visibility="visible")</script>
