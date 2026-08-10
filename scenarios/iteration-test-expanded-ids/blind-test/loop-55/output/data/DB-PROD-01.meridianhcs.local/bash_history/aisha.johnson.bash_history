#1710766240
systemctl is-active mysql
#1710766252
journalctl -u mysql -n 200 --no-pager
#1710766280
ps aux | grep mysql
#1710766479
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710766533
hostnamectl
#1710771841
systemctl status sshd --no-pager
#1710772216
journalctl -u sshd -n 20 --no-pager
#1710772284
ss -ltnp | grep mysql
#1710772329
systemctl cat sshd 2>/dev/null | head -40
#1710784293
systemctl status mysql
#1710784317
cd /tmp
#1710784389
grep -i 'failed password' /var/log/auth.log | wc -l
#1710784646
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710784691
journalctl -u sshd --since '30 min ago' --no-pager | tail -20
