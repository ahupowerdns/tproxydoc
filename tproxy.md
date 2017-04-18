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
to the authoritative sources.

Some of the "pseudocode" examples actually compile when used with
[SimpleSockets](https://github.com/ahupowerdns/simplesocket). This is used
because these examples are easier to read than the somewhat cumbersome raw
BSD sockets API equivalent.

How it works from userspace
---------------------------
Regular sockets are used for transparent proxying, but a special flag,
IP_TRANSPARENT, is set to indicate that this socket might receive
connections for non-local addresses, or send from non-local addresses.

This already is useful without any further work to spoof the source address
of a UDP packet:

```
  Socket s(AF_INET, SOCK_DGRAM, 0);
  SSetsockopt(s, IPPROTO_IP, IP_TRANSPARENT, 1);
  ComboAddress local("1.2.3.4", 5300);
  ComboAddress remote("198.41.0.4", 53);
  
  SBind(s, local);
  SSendto(s, "hi!", remote);
```

Note: this requires root or CAP_NET_ADMIN to work. When run, you can observe
with tcpdump that an actual packet leaves the host:

```
21:29:41.005856 IP 1.2.3.4.5300 > 198.41.0.4.53: [|domain]
```

IP_TRANSPARENT is mentioned in
[ip(7)](http://man7.org/linux/man-pages/man7/ip.7.html).

The iptables part
-----------------
Before an IP_TRANSPARENT socket works, Linux has to take the packet out of
the routing process and hand it to userspace. 

To do so, `iptables` has a target called TPROXY which performs part of the
work required.

In short, TPROXY prepares packets for handing over to a local socket,
without changing source or destination headers. Note that it only prepares,
more work remains to be done.

The basic syntax is:

```
iptables -t mangle -A PREROUTING -p tcp --dport 25 -j TPROXY \
  --tproxy-mark 0x1/0x1 --on-port 10025 --on-ip 127.0.0.1
```

This says: take everything destined for a port 25 on TCP and prepare this
for a process listening on 127.0.0.1:10025 and mark the packet with 1.



The routing part
================
Once marked and prepared, the packet still has the same destination address
and will happily zoom out of the router again without being handed to your
process.

To make this happen, a policy rule needs to be set on packets marked with
the mark 1:

```
ip rule add fwmark 1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
```

This says that all packets marked with '1' go to routing table 100, and this
table then says 'all IPv4 addresses are local'. 

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

Practical details
=================
For TCP sockets, the original destination address and port of a socket is
available via `getsockname()`.  This is needed for exampel to setup a
connection to the originally intended destination.

For UDP, the IP_RECVORIGDSTADDR socket option can be set with
`setsockopt()`. To actually get to that address, `recvmsg()` must be used
which will then pass the original destination as a cmsg with index
IP_ORIGDSTADDR containing a struct sockaddr_in.

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
