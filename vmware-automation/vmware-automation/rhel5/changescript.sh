hostName=$1
ipAddress=$2
netMask=$3
gateway=$4
dns1=$5
dns2=$6
suffix=".dev.medfusion.net"
fqdnName=$hostName$suffix
ifconfig eth0 $ipAddress netmask $netMask
route add default gw $gateway
echo "IPADDR=$ipAddress" >> /etc/sysconfig/network-scripts/ifcfg-eth0
echo "NETMASK=$netMask" >> /etc/sysconfig/network-scripts/ifcfg-eth0
echo "GATEWAY=$gateway" >> /etc/sysconfig/network-scripts/ifcfg-eth0
echo "DNS1=$dns1" >> /etc/sysconfig/network-scripts/ifcfg-eth0
if [ ! -z "$dns2" -a "$dns2"!=" " ]; then
echo "DNS2=$dns2" >> /etc/sysconfig/network-scripts/ifcfg-eth0
fi
sed  -i -e  's/<agent controller="172.18.81.74:1337" name="">/<agent controller="172.18.81.74:1337" name="'$hostName'">/g' /opt/leroy_agent/agent.xml > /dev/null
sed  -i -e  's#\(<property name="agentName">\)\(</property>\)#\1'$hostName'\2#g' /opt/leroy_agent/agent.xml > /dev/null
oldhostname=$(cat /etc/sysconfig/network | grep HOSTNAME | cut -d '=' -f 2)
sed -i -e 's/'$oldhostname'/'$fqdnName'/g' /etc/sysconfig/network > /dev/null
/bin/hostname $fqdnName
cd /opt/leroy_agent
chmod u+x *.sh
./install-agent.sh
./check-agent-running.sh > /dev/null 2>&1
service network restart
