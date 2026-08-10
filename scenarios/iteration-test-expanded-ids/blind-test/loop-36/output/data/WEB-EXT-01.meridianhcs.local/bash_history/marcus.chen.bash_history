#1710766313
cat /proc/cpuinfo | grep 'model name' | head -1
#1710766427
mount | column -t
#1710766463
find /var/log -name '*.gz' -mtime +30 | wc -l
#1710766512
echo $SHELL
#1710766769
systemctl status sshd
#1710766821
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710767048
du -sh /home/* 2>/dev/null | head
#1710767070
cd -
#1710782768
hostname -f
#1710782850
ls -ltr
#1710782932
history | tail -15
#1710782942
dmesg --ctime | tail -20
#1710783288
top -bn1 | head -20
#1710783364
iptables -L -n
#1710783371
loginctl session-status
