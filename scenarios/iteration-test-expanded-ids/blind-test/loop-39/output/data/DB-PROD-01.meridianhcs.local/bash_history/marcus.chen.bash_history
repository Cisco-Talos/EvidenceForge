#1710773178
systemctl status sshd --no-pager
#1710773310
journalctl -u mysql --since '30 min ago' --no-pager | tail -20
#1710773342
ss -ltnp | grep mysql
#1710773707
systemctl show mysql -p ActiveState -p SubState -p MainPID
#1710773883
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710773892
dmesg | tail -30
#1710773947
iptables -L -n
#1710778868
systemctl is-active mysql
#1710779203
journalctl -u mysql -n 50 --no-pager
#1710779217
ps aux | grep mysql
#1710779269
systemctl cat mysql 2>/dev/null | head -40
#1710779337
mount | column -t
#1710779348
cat /etc/hosts
#1710779398
who -a
#1710780112
systemctl status mysql --no-pager
#1710780190
journalctl -u mysql -n 20 --no-pager
#1710780592
ss -ltnp | grep mysql
#1710780648
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710780660
tail -f /var/log/syslog &
#1710780735
w
#1710780769
groups
#1710781031
lsmod | head
#1710781097
yum check-update 2>/dev/null
#1710781144
cat /proc/meminfo | head -5
