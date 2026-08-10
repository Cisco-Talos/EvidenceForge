#1710768147
hostnamectl
#1710768691
ss -s
#1710768783
systemctl --failed --no-pager
#1710768967
iptables -L -n
#1710769297
systemctl status systemd-resolved
#1710769310
pwd
#1710769380
systemd-analyze blame | head
#1710769444
journalctl -u apache2 -n 20
#1710769636
mount | column -t
#1710769648
cat /proc/meminfo | head -5
#1710769810
du -sh /tmp/*
#1710769865
du -sh /var/log
#1710769911
who
#1710772091
systemctl status sshd --no-pager
#1710772319
journalctl -u apache2 -n 50 --no-pager
#1710772382
ps aux | grep apache2
#1710772442
systemctl cat apache2 2>/dev/null | head -40
#1710772477
lsblk
#1710772526
ss -ltnp | grep sshd
#1710772582
ip -o addr show scope global
#1710772877
echo $SHELL
#1710772888
tail -20 /var/log/syslog
#1710773193
top -bn1 | head -20
#1710773520
resolvectl query login.microsoftonline.com
#1710774301
whoami
#1710774607
ls -lh
#1710774682
date
#1710774762
dmesg | tail -30
#1710774803
ip route
#1710774830
ss -ltnp | grep systemd-resolved
#1710775232
dj
#1710775245
ls -la
#1710775333
journalctl -p err --no-pager -n 10
#1710775341
who -a
#1710775436
grep -i error /var/log/syslog | tail -50
