#1710765684
cat /etc/resolv.conf
#1710765916
cat /etc/hosts
#1710766327
ss -tan | head
#1710766415
tail -20 ~/.bash_history
#1710775458
tail -20 /var/log/syslog
#1710775548
loginctl session-status
#1710775586
journalctl -u systemd-resolved -n 100
#1710776593
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710776925
cat /proc/meminfo | head -5
#1710777249
systemd-analyze blame | head
#1710777314
groups
#1710777340
systemctl list-timers --all --no-pager | head
#1710779652
ip -o addr show scope global
#1710779660
timedatectl
#1710779759
resolvectl status 2>/dev/null | head -30
#1710779936
env | sort | head
#1710780002
netstat -an | grep ESTABLISHED | wc -l
#1710780278
systemctl status systemd-resolved
#1710780290
cat /etc/fstab
#1710780319
journalctl -u sshd -n 100
#1710780661
ls /var/log
#1710780719
ls -la
#1710780880
env | head -20
#1710780893
loginctl user-status
#1710780915
ss -tan | head
#1710783067
tail -50 /var/log/auth.log
#1710783287
grep -i 'failed password' /var/log/auth.log | tail -20
#1710783674
ca
#1710783746
ss -ltnp | grep gunicorn
#1710783831
grep -i 'session opened' /var/log/auth.log | tail -10
#1710783899
systemctl status gunicorn
#1710783997
crontab -l
#1710784005
grep -i 'failed password' /var/log/auth.log | wc -l
#1710784189
ulimit -n
#1710784218
systemctl list-timers
#1710784452
systemctl list-timers --all --no-pager | head
#1710784545
pwd
#1710784711
clear
