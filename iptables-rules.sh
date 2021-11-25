#!/bin/bash
# Author: Manuel Mehltretter
# Basic IP Tables Firewall
# For more information check https://wiki.archlinux.org/title/simple_stateful_firewall

##
# Initial Setup, DO NOT TOUCH
##

#Flush settings, create chains, set default policies
iptables -F
iptables -X
iptables -t raw -F
iptables -N TCP
iptables -N UDP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -P INPUT DROP

#Protect against spoofing Attacks
iptables -t raw -I PREROUTING -m rpfilter --invert -j DROP

# Allow traffic on the loopback interface and allow established connections, drop invalid connections
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# Allow Ping
iptables -A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT

# Forward new UDP traffic to the UDP chain
iptables -A INPUT -p udp -m conntrack --ctstate NEW -j UDP
# Forward new TCP traffic with only SIN Flag to the TCP chain, all other traffic is malicious
iptables -A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP

# Reject all other traffic, while imitating the Linux default behavior and protecting against portscans
iptables -A INPUT -p tcp -m recent --set --rsource --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset
iptables -A INPUT -p udp -m recent --set --rsource --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable

##
# TCP Rules, DO NOT TOUCH
##

###Protection against SYN scans
iptables -I TCP -p tcp -m recent --update --rsource --seconds 60 --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset

###Custom TCP Rules below this block 
#Allow SSH
iptables -A TCP -p tcp --dport 22 -j ACCEPT
#Allow HTTP
iptables -A TCP -p tcp --dport 80 -j ACCEPT
#Allow HTTPS
iptables -A TCP -p tcp --dport 443 -j ACCEPT
#Allow LDAPS
iptables -A TCP -p tcp --dport 636 -j ACCEPT

##
# UDP Rules
##

###Protection against UDP scans
iptables -I UDP -p udp -m recent --update --rsource --seconds 60 --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable

###Custom UDP Rules below this block



### Final Rule imitating Linux behavior, DO NOT TOUCH
iptables -A INPUT -j REJECT --reject-with icmp-proto-unreachable

##
# Deny all IPv6, DO NOT TOUCH
##
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
ip6tables -A INPUT -p udp -j REJECT --reject-with icmp6-adm-prohibited
ip6tables -A INPUT -p tcp -j REJECT --reject-with tcp-reset
ip6tables -A INPUT -j REJECT --reject-with icmp6-adm-prohibited
