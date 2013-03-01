synproxy
========

Based on https://github.com/xiaosuo/xiaosuo/tree/master/synproxy

synproxy:
It is an implementation of SYNPROXY based on netfilter of Linux. An iptables raw
target SYNPROXY is implemented. In order to use it, you must get the newest
Linux kernel source code, and follow the following steps:
	cd linux
	patch -p1 < path-to-synproxy.diff
	/* you need select raw table, ip_conntrack and syncookies */
	make && make install modules_install && reboot
	cd path-to-synproxy
	make
	cp libipt_SYNPROXY.so path-to-iptables-shared-module
	insmod ipt_SYNPROXY.ko
If there isn't any error in the above steps, congratulations, and you can play
with it. For example, you want to protect the local HTTP server from the
SYN-flood attacks:
	iptables -t nat -A OUTPUT -p tcp --dport 80 -d XXX.XXX.XXX.XXX -j DNAT --to-destination XXX.XXX.XXX.XXX:80
	iptables -t raw -A PREROUTING -p tcp -d XXX.XXX.XXX.XXX --dport 80 --tcp-flags SYN,ACK,RST,FIN SYN -j SYNPROXY
	

