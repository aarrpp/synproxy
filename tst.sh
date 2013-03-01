iptables -t raw -F
rmmod ipt_SYNPROXY
insmod ipt_SYNPROXY.ko
iptables -t raw -A PREROUTING -p tcp --dport 80 --tcp-flags SYN,ACK,RST,FIN SYN\
	-m conntrack --ctstate INVALID -j SYNPROXY
