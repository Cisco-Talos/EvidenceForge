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
#1710775988
systemctl is-active systemd-resolved
#1710776000
journalctl -u postfix -n 20 --no-pager
#1710776021
ss -ltnp | grep imaps
#1710776100
systemctl cat postfix 2>/dev/null | head -40
#1710776142
last -20
#1710776560
ps -ef | head
#1710776574
journalctl --no-pager -n 5
#1710776604
df -h /
#1710776690
whoami
#1710777080
id
#1710777528
ls -lh
#1710778428
systemctl is-active smtp
#1710778569
journalctl -u imaps --since '30 min ago' --no-pager | tail -50
#1710779092
ss -ltnp | grep systemd-resolved
#1710779184
systemctl cat imaps 2>/dev/null | head -40
#1710779213
free -h
#1710779275
locale
#1710779299
tail -20 /var/log/syslog
#1710779387
ll
#1710779484
cat /etc/hostname
#1710780735
who -a
#1710780876
ip route
#1710781850
systemctl restart dovecot
#1710781952
nmcli connection show --active
#1710782567
netstat -an | grep ESTABLISHED | wc -l
#1710783645
htop
#1710783733
systemctl list-timers
#1710783891
tail -200 /var/log/syslog
#1710784060
crontab -l
#1710784111
journalctl -u sshd --since '1 hour ago'
