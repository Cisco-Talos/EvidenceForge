#1710763819
timedatectl
#1710763830
resolvectl query login.microsoftonline.com
#1710765220
who -a
#1710765473
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710765613
grep -i 'session opened' /var/log/auth.log | tail -20
#1710765970
nmcli connection show --active
#1710766347
uname -sr
#1710766873
date
#1710766904
cat /proc/meminfo | head -5
#1710767485
getent passwd $(whoami)
#1710767537
timedatectl
#1710784064
ps aux
#1710784143
cat /etc/fstab
#1710784364
ls -lh
#1710784455
cat /etc/hostname
#1710784520
journalctl -xe --no-pager | tail -20
#1710784605
cd /var/log
#1710784700
ss -ltnp | grep imaps
#1710784707
env | sort | head
#1710784796
resolvectl query login.microsoftonline.com
