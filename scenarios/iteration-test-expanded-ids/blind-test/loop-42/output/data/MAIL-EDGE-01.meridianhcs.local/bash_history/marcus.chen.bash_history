#1710763362
hostname -f
#1710766051
hostname -f
#1710766529
ls -ltr
#1710766581
history | tail -15
#1710766955
hostnamectl
#1710771833
hostname -f
#1710772098
ls -lh
#1710772119
history | tail -15
#1710772128
whoami
#1710772261
tail -100 /var/log/auth.log
#1710772671
iptables -L -n
#1710773071
ls -lt /var/log | head
#1710773159
ss -ltnp | grep imaps
#1710773173
loginctl session-status
#1710773236
cat /etc/hosts
#1710773449
ip -o addr show scope global
#1710773579
command -v python3
#1710773982
who
#1710775921
ls -lah
#1710775999
htop
#1710776658
systemctl status smtp
#1710776754
cat /etc/fstab
#1710777166
loginctl user-status
#1710777308
ip route
#1710777374
dmesg | tail -30
#1710778584
ss -s
#1710778622
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -20
#1710778689
journalctl --since '10 min ago' --no-pager -n 20
#1710778701
netstat -an | grep ESTABLISHED | wc -l
#1710778872
udevadm info --query=property --name=/dev/null | head
#1710784217
resolvectl query login.microsoftonline.com
#1710784545
df -h /var
#1710784665
lsblk
