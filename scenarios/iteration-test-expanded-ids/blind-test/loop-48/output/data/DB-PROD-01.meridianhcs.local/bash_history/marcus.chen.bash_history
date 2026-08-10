#1710771465
journalctl -u mysql --since '30 min ago' --no-pager | tail -20
#1710771814
ulimit -n
#1710772157
systemctl status mysql
#1710772447
tail -20 /var/log/syslog
#1710772612
ip route
#1710772675
mount | column -t
#1710772686
ss -ltnp | grep sshd
#1710772744
cat /proc/meminfo | head -5
#1710772756
loginctl session-status
#1710772830
hostname
#1710773164
last -5
#1710773205
iptables -L -n
#1710781107
udevadm info --query=property --name=/dev/null | head
