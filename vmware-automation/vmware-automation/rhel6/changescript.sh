hostName=$1
ipAddress=$2
netMask=$3
gateway=$4
dns1=$5
dns2=$6
rm -f /etc/udev/rules.d/70-persistent-net.rules
start_udev
sed -i -e 's/eth1/eth0/g' /etc/udev/rules.d/70-persistent-net.rules > /dev/null
start_udev
ifconfig eth0 $ipAddress netmask $2
route add default gw $3
echo "IPADDR=$ipAddress" >> /etc/sysconfig/network-scripts/ifcfg-eth0
echo "NETMASK=$netMask" >> /etc/sysconfig/network-scripts/ifcfg-eth0
echo "GATEWAY=$gateway" >> /etc/sysconfig/network-scripts/ifcfg-eth0
echo "DNS1=$dns1" >> /etc/sysconfig/network-scripts/ifcfg-eth0
if [ ! -z "$dns2" -a "$dns2"!=" " ]; then 
	echo "DNS2=$dns2" >> /etc/sysconfig/network-scripts/ifcfg-eth0
fi
sed  -i -e  's#\(<property name="agentName">\)\(</property>\)#\1'$hostName'\2#g' /opt/leroy_agent/agent.xml > /dev/null
oldhostname=$(cat /etc/sysconfig/network | grep HOSTNAME | cut -d '=' -f 2)
sed -i -e 's/'$oldhostname'/'$hostName'/g' /etc/sysconfig/network > /dev/null 
service network restart
