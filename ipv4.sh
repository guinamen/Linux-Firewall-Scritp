#!/bin/sh
##################################################################
##Firewall configuration script
##The script objective is create a firewall configuration
##for service in format <IN OUT>:<PROTOCOL>@<IP IP/NETWORK>:<PORT>
##################################################################

#Firewall  tools
IPT="/sbin/iptables"
IPT_ARP="/sbin/arptables"

#Interface
INTERFACE=$1

#Networ definitions
LOOPBACK="127.0.0.0/8"
CLASS_A="10.0.0.0/8"
CLASS_B="172.16.0.0/12"
CLASS_C="192.168.0.0/16"
CLASS_D_MULTICAST="224.0.0.0/4"
CLASS_E_RESERVED_NET="240.0.0.0/5"
#Up ports
UP_PORTS="1024:65535"
TR_SRC_PORTS="32769:65535"
TR_DEST_PORTS="33434:33523"


#Networ address calculator
function networkCalc () {
  IFS=. read -r i1 i2 i3 i4 <<< $1
  IFS=. read -r xx m1 m2 m3 m4 <<< $(
	for a in $(seq 1 32);
          do
            if [ $(((a - 1) % 8)) -eq 0 ];
            then
               printf ".";
            fi;
            if [ $a -le $2 ];
              then
                printf "%d" 1;
              else
                printf "%d" 0;
              fi;
          done)
  printf "%d.%d.%d.%d/%d" "$((i1 & (2#$m1)))" "$((i2 & (2#$m2)))" "$((i3 & (2#$m3)))" "$((i4 & (2#$m4)))" "$2"
  return 0
}

#Process a list of service in format <IN OUT>:<PROTOCOL>@<SOURCE IP OR IP/NETWORK>|<DESTINY IP OR NETWORK>:<PORT>
function allowIn() {
  for SERVICE in $@;
  do
    local FLOW=""
    local PROTOCOL=""
    local IP=""
    local PORT=""
    $IPT -A INPUT  -i $INTERFACE -p $PROTOCOL -s $INTERFACE_NET -d $INTERFACE_IP --sport $UP_PORTS --dport $PORT     -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -o $INTERFACE -p $PROTOCOL -s $INTERFACE_IP  -d 0/0           --sport $PORT     --dport $UP_PORTS -m state --state ESTABLISHED     -j ACCEPT
  done
  return 0
}

#Allow arp protocols
function allowArp() {
  ARP_TABLE=$(arp -e)
  for ARP_TRUST_IP in $@;
  do
    if ! grep $ARP_TRUST_IP <<< $ARP_TABLE;
    then
      ping $ARP_TRUST_IP -c 1 -q >> /dev/null
      if [ $? -eq 0 ]
      then
	MAC=$(arp | grep $ARP_TRUST_IP | awk '{print $3}')
      else
        continue
      fi
    else
      MAC=$(arp | grep $ARP_TRUST_IP | awk '{print $3}')
    fi
    $IPT_ARP -A INPUT  -s $ARP_TRUST_IP --source-mac $MAC -j ACCEPT
    $IPT_ARP -A OUTPUT -d $ARP_TRUST_IP --destination-mac $MAC -j ACCEPT
  done
  return 0
}

INTERFACE_INFO=$(ip addr show dev ${INTERFACE})
INTERFACE_MAC=$(awk 'NR==2 {print $2}' <<<  "$INTERFACE_INFO" )
INTERFACE_IP=$(awk 'NR==3 {print $2}' <<< "$INTERFACE_INFO" | sed 's/\/.*//')
INTERFACE_NET_PREFIX=$(awk 'NR==3{print $2}' <<< "$INTERFACE_INFO" | sed 's/[^\/]*\///g')
INTERFACE_BROADCAST=$(awk 'NR==3 {print $4}' <<< "$INTERFACE_INFO" | sed 's/\/.*//')
# Network adress calculator
INTERFACE_NET=$(networkCalc ${INTERFACE_IP} ${INTERFACE_NET_PREFIX})
ROUTER=$(ip route show dev ${INTERFACE}  | awk 'NR==1 {print $3}')
#DNS configuration
DNS_SERVERS=$(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /etc/resolv.conf | tr '\n' ' ')

#IN
#Trusted in ports
GENERAL_SERVER_PORTS="22 80 443"
#Trusted in server and port
SPECIFIC_SERVER_PORTS="10.0.58.193:9090 10.0.58.193:9091"

#OUT
#Trusted out ports
GENERAL_CLIENT_PORTS="20 21 22 80 443"
#Trust out server and port
SPECIFIC_CLIENT_PORTS="cachepbh.pbh:3128"

#Up ports
UP_PORTS="1024:65535"
TR_SRC_PORTS="32769:65535"
TR_DEST_PORTS="33434:33523"

#Configurations
LOG=true
LOG_LIMIT=true
ARP=true

#Trusted network ips
ARP_TRUST_IPS="$ROUTER 10.0.59.137"

if [ "$ARP" = true ] ;
then
  #Clean rules
  $IPT_ARP -F
  $IPT_ARP -X
  allowArp $ARP_TRUST_IPS
  #Setting default filter policy
  $IPT_ARP -P INPUT DROP
  $IPT_ARP -P OUTPUT DROP
fi
# Flushing all rules
$IPT -F
$IPT -X
$IPT -Z

# Setting default filter policy
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# Allow unlimited traffic on loopback
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

## SYN-FLOODING PROTECTION
$IPT -N syn-flood
$IPT -A INPUT -i $INTERFACE -p tcp --syn -j syn-flood
$IPT -A syn-flood -m limit --limit 1/s --limit-burst 4 -j RETURN
$IPT -A syn-flood -j DROP


## Make sure NEW tcp connections are SYN packets
#$IPT -A INPUT -i $INTERFACE -p tcp ! --syn -m state --state NEW -j DROP

## FRAGMENTS
$IPT -A INPUT -i $INTERFACE -f -j LOG --log-prefix "$IPT FRAGMENTS: "
$IPT -A INPUT -i $INTERFACE -f -j DROP

## SPOOFING
# Most of this anti-spoofing stuff is theoretically not really necessary with the flags we
# have set in the kernel above ........... but you never know there isn't a bug somewhere in
# your IP stack.
#
# Refuse spoofed packets pretending to be from your IP address.
$IPT -A INPUT  -i $INTERFACE -s $INTERFACE_IP -j DROP
# Refuse packets claiming to be from a Class A private network.
#$IPT -A INPUT  -i $INTERFACE -s $CLASS_A -j DROP
# Refuse packets claiming to be from a Class B private network.
$IPT -A INPUT  -i $INTERFACE -s $CLASS_B -j DROP
# Refuse packets claiming to be from a Class C private network.
$IPT -A INPUT  -i $INTERFACE -s $CLASS_C -j DROP
# Refuse Class D multicast addresses. Multicast is illegal as a source address.
$IPT -A INPUT -i $INTERFACE -s $CLASS_D_MULTICAST -j DROP
# Refuse Class E reserved IP addresses.
$IPT -A INPUT -i $INTERFACE -s $CLASS_E_RESERVED_NET -j DROP

# Refuse packets claiming to be to the loopback interface.
# Refusing packets claiming to be to the loopback interface protects against
# source quench, whereby a machine can be told to slow itself down by an icmp source
# quench to the loopback.
$IPT -A INPUT  -i $INTERFACE -d $LOOPBACK -j DROP
# Refuse broadcast address packets.
$IPT -A INPUT -i $INTERFACE -d $INTERFACE_BROADCAST -j DROP


# Allow inbound
for PORT in $GENERAL_SERVER_PORTS
do
  $IPT -A INPUT  -i $INTERFACE -p tcp -s $INTERFACE_NET -d $INTERFACE_IP --sport $UP_PORTS --dport $PORT -m state --state NEW,ESTABLISHED -j ACCEPT
  $IPT -A OUTPUT -o $INTERFACE -p tcp -s $INTERFACE_IP -d 0/0 --sport $PORT --dport $UP_PORTS -m state --state ESTABLISHED -j ACCEPT
done

for SPECIFIC_SERVER_PORT in $SPECIFIC_SERVER_PORTS
do
  IFS=':' read -r SERVER PORT <<< "$SPECIFIC_SERVER_PORT"
  $IPT -A INPUT  -i $INTERFACE -p tcp -s $INTERFACE_NET -d $INTERFACE_IP --sport $UP_PORTS --dport $PORT -m state --state NEW,ESTABLISHED -j ACCEPT
  $IPT -A OUTPUT -o $INTERFACE -p tcp -s $INTERFACE_IP -d $SERVER --sport $PORT --dport $UP_PORTS -m state --state ESTABLISHED -j ACCEPT
done

#Allow DNS consult
for DNS_SERVER in $DNS_SERVERS
do
  $IPT -A OUTPUT -p udp -s $INTERFACE_IP --sport $UP_PORTS -d $DNS_SERVER --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
  $IPT -A INPUT  -p udp -s $DNS_SERVER --sport 53 -d $INTERFACE_IP --dport $UP_PORTS -m state --state ESTABLISHED -j ACCEPT

  $IPT -A OUTPUT -p tcp -s $INTERFACE_IP --sport $UP_PORTS -d $DNS_SERVER --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
  $IPT -A INPUT  -p tcp -s $DNS_SERVER --sport 53 -d $INTERFACE_IP --dport $UP_PORTS -m state --state ESTABLISHED -j ACCEPT
done

#Allow Server clients
for SERVER_CLIENT in $SPECIFIC_CLIENT_PORTS
do
  IFS=':' read -r SERVER PORT <<< "$SERVER_CLIENT"
  $IPT -A OUTPUT -p tcp -s $INTERFACE_IP --sport $UP_PORTS -d $SERVER --dport $PORT -m state --state NEW,ESTABLISHED -j ACCEPT
  $IPT -A INPUT  -p tcp -s $SERVER --sport $PORT -d $INTERFACE_IP --dport $UP_PORTS -m state --state ESTABLISHED -j ACCEPT
done

#Allow outbound
for PORT in $GENERAL_CLIENT_PORTS
do
  $IPT -A INPUT  -i $INTERFACE -p tcp --sport $PORT -m state --state ESTABLISHED     -j ACCEPT
  $IPT -A OUTPUT -o $INTERFACE -p tcp --dport $PORT -m state --state NEW,ESTABLISHED -j ACCEPT
done

## FTP
# Passive ftp.
# This involves a connection outbound from a port >1023 on the local machine, to a port >1023
# on the remote machine previously passed over the ftp channel via a PORT command. The
# ip_conntrack_ftp module recognizes the connection as RELATED to the original outgoing
# connection to port 21 so we don't need NEW as a state match.
$IPT -A INPUT  -i $INTERFACE -p tcp --sport $UP_PORTS --dport $UP_PORTS -m state --state ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INTERFACE -p tcp --sport $UP_PORTS --dport $UP_PORTS -m state --state ESTABLISHED,RELATED -j ACCEPT

##Auth
# Reject ident probes with a tcp reset.
$IPT -A INPUT  -i $INTERFACE -p tcp --dport 113 -j REJECT --reject-with tcp-reset

## TRACEROUTE
# Outgoing traceroute anywhere.
$IPT -A OUTPUT -o $INTERFACE -p udp --sport $TR_SRC_PORTS --dport $TR_DEST_PORTS -m state --state NEW -j ACCEPT

# ICMP
$IPT -A INPUT  -i $INTERFACE -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -o $INTERFACE -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

## AUTH server
$IPT -A INPUT  -i $INTERFACE -p tcp --dport 113 -j REJECT --reject-with tcp-reset

## TRACEROUTE
$IPT -A OUTPUT -o $INTERFACE -p udp --sport $TR_SRC_PORTS --dport $TR_DEST_PORTS -m state --state NEW -j ACCEPT

# ICMP
$IPT -A INPUT  -i $INTERFACE -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -o $INTERFACE -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT


## LOGGING
# You don't have to split up your logging like I do below, but I prefer to do it this way
# because I can then grep for things in the logs more easily. One thing you probably want
# to do is rate-limit the logging. I didn't do that here because it is probably best not too
# when you first set things up ................. you actually really want to see everything going to
# the logs to work out what isn't working and why. You cam implement logging with
# "-m limit --limit 6/h --limit-burst 5" (or similar) before the -j LOG in each case.
#
# Any udp not already allowed is logged and then dropped.
if [ "$LOG" = true ] ;
then
  if [ "$LOG_LIMIT" = true ] ;
  then
    LIMIT="-m limit --limit 1/m --limit-burst 5"
  else
    LIMIT=""
  fi
  $IPT -A INPUT  -i $INTERFACE -p udp $LIMIT -j LOG --log-prefix "IPT UDP-IN: " --log-level info
  $IPT -A INPUT  -i $INTERFACE -p udp -j DROP
  $IPT -A OUTPUT -o $INTERFACE -p udp $LIMIT -j LOG --log-prefix "IPT UDP-OUT: " --log-level info
  $IPT -A OUTPUT -o $INTERFACE -p udp -j DROP
  # Any icmp not already allowed is logged and then dropped.
  $IPT -A INPUT  -i $INTERFACE -p icmp $LIMIT -j LOG --log-prefix "IPT ICMP-IN: " --log-level info
  $IPT -A INPUT  -i $INTERFACE -p icmp -j DROP
  $IPT -A OUTPUT -o $INTERFACE -p icmp $LIMIT -j LOG --log-prefix "IPT ICMP-OUT: " --log-level info
  $IPT -A OUTPUT -o $INTERFACE -p icmp -j DROP
  # Any tcp not already allowed is logged and then dropped.
  $IPT -A INPUT  -i $INTERFACE -p tcp $LIMIT -j LOG --log-prefix "IPT TCP-IN: " --log-level info
  $IPT -A INPUT  -i $INTERFACE -p tcp -j DROP
  $IPT -A OUTPUT -o $INTERFACE -p tcp $LIMIT -j LOG --log-prefix "IPT TCP-OUT: " --log-level info
  $IPT -A OUTPUT -o $INTERFACE -p tcp -j DROP
  # Anything else not already allowed is logged and then dropped.
  # It will be dropped by the default policy anyway ........ but let's be paranoid.
  $IPT -A INPUT  -i $INTERFACE -j LOG --log-prefix "IPT PROTOCOL-X-IN: "
  $IPT -A INPUT  -i $INTERFACE -j DROP
  $IPT -A OUTPUT -o $INTERFACE -j LOG --log-prefix "IPT PROTOCOL-X-OUT: "
  $IPT -A OUTPUT -o $INTERFACE -j DROP
fi

# make sure nothing comes or goes out of this box
$IPT -A INPUT -j DROP
$IPT -A OUTPUT -j DROP
