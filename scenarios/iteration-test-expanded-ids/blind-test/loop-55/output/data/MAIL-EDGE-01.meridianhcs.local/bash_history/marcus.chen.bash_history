#1710768711
systemctl status systemd-resolved --no-pager
#1710768720
journalctl -u postfix -n 100 --no-pager
#1710769014
ss -ltnp | grep systemd-resolved
#1710769107
systemctl cat postfix 2>/dev/null | head -40
#1710769204
echo $SHELL
#1710769232
ip -br addr
#1710769239
netstat -an | grep ESTABLISHED | wc -l
#1710769539
file /usr/bin/ls
#1710769612
journalctl -u dovecot --since '30 min ago' --no-pager | tail -20
#1710769802
op
#1710769863
ip route get 8.8.8.8
#1710770215
systemd-analyze blame | head
#1710770226
resolvectl query login.microsoftonline.com
#1710773845
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710773913
loginctl session-status
#1710773936
ll
#1710773945
date -u
#1710776824
tail -20 /var/log/auth.log
#1710776930
free -h
#1710777134
ls -lt /var/log | head
#1710777336
find /tmp -maxdepth 1 -type f | head
#1710778795
tail -20 ~/.bash_history
#1710778939
last -20
#1710779024
udevadm info --query=property --name=/dev/null | head
#1710780531
ps -ef | head
#1710780624
tail -f /var/log/syslog &
#1710780983
systemctl status NetworkManager --no-pager
#1710781039
journalctl -p err --no-pager -n 10
#1710781101
lsblk
#1710781200
du -sh /home/* 2>/dev/null | head
#1710781262
tail -20 /var/log/syslog
#1710781273
du -sh /var/log/*
#1710781566
df -h
#1710781574
cat /etc/os-release
#1710781896
cat /etc/passwd | head
#1710782024
ls -lah
#1710782112
grep -i warning /var/log/syslog | tail
#1710782133
journalctl -u dovecot --since '30 min ago' --no-pager | tail -20
#1710782143
cat /etc/resolv.conf
#1710782231
env | sort | head
