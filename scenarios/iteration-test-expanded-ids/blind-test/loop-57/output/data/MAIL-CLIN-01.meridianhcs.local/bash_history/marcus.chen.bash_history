#1710763832
uptime
#1710764164
free -h
#1710765171
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710765266
systemctl --failed --no-pager
#1710765298
who -a
#1710765589
cd ~
#1710765624
ip route
#1710765874
mount | column -t
#1710766095
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710766163
systemctl is-active postfix
#1710766317
journalctl -u smtp -n 50 --no-pager
#1710766592
ps aux | grep smtp
#1710766684
systemctl show systemd-resolved -p ActiveState -p SubState -p MainPID
#1710766733
journalctl -u sshd --since '1 hour ago'
#1710766775
ip -br addr
#1710768063
tail -50 /var/log/auth.log
#1710768543
grep -i 'failed password' /var/log/auth.log | tail -20
#1710768680
systemctl list-units --failed
#1710768741
python3 -V 2>&1
#1710768794
grep -i 'failed password' /var/log/auth.log | wc -l
#1710768824
cat /etc/crontab
#1710768834
who
#1710768875
cat /etc/passwd | head
#1710768884
grep -i error /var/log/syslog | tail
#1710768973
journalctl -u dovecot --since '30 min ago' --no-pager | tail -20
#1710768984
ss -ltnp | grep systemd-resolved
#1710769032
systemctl restart postfix
#1710769096
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710769271
lsblk
#1710769278
systemctl list-timers
#1710773951
hostname -f
#1710777048
tail -200 /var/log/auth.log
#1710777310
grep -i 'session opened' /var/log/auth.log | tail -20
#1710777378
ls /var/log
#1710777437
htop
#1710777514
systemctl list-timers
#1710777554
ps aux | grep imaps
#1710777644
cd ~
#1710777952
cat /proc/version | cut -d' ' -f1-3
#1710778006
journalctl --no-pager -n 5
