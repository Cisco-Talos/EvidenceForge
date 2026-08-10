#1710775206
who -a
#1710775260
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710775545
grep -i 'failed password' /var/log/auth.log | tail -20
#1710775622
fiel
#1710775636
grep -i warning /var/log/syslog | tail
#1710775661
systemctl restart systemd-resolved
#1710775732
cd -
#1710775818
resolvectl query company.okta.com
#1710776123
du -sh /var/log/*
#1710776188
iptables -L -n
#1710776273
cat /etc/hosts
#1710776286
journalctl -u postfix --since '30 min ago' --no-pager | tail -20
#1710776379
iostat -x 1 3
#1710776577
cat /etc/fstab
#1710783496
systemctl status imaps --no-pager
#1710783548
journalctl -u dovecot -n 20 --no-pager
#1710783965
ss -ltnp | grep smtp
#1710784057
systemctl show postfix -p ActiveState -p SubState -p MainPID
#1710784399
resolvectl status 2>/dev/null | head -30
#1710784486
grep -i error /var/log/syslog | tail
#1710784555
tail -50 /var/log/syslog
#1710784640
tail -f /var/log/syslog &
