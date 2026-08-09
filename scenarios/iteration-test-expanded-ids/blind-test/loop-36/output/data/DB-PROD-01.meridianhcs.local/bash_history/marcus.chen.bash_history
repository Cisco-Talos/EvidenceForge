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
#1710778424
systemctl status mysql --no-pager
#1710778754
journalctl -u mysql -n 50 --no-pager
#1710778765
ps aux | grep mysql
#1710779047
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710779056
systemctl restart sshd
#1710779091
ls -la
#1710779303
du -sh /tmp/*
#1710779362
find /var/log -name '*.gz' -mtime +30 | wc -l
#1710779541
tail -f /var/log/syslog &
#1710779890
lsblk
#1710780963
ss -tulnp
#1710783004
systemctl is-active mysql
#1710783100
journalctl -u sshd --since '30 min ago' --no-pager | tail -100
#1710783179
ps aux | grep sshd
#1710783695
systemctl show mysql -p ActiveState -p SubState -p MainPID
#1710783789
vmstat 1 5
#1710783854
grep -i 'session opened' /var/log/auth.log | tail -10
#1710784115
tail -200 /var/log/auth.log
#1710784172
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710784205
resolvectl query company.okta.com
#1710784253
dnf check-update 2>/dev/null
#1710784415
resolvectl query login.microsoftonline.com
#1710784626
ls -lt /var/log | head
#1710784673
systemctl status NetworkManager --no-pager
