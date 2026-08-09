#1710765118
last -20
#1710765124
tail -200 /var/log/auth.log
#1710766442
grep -i 'failed password' /var/log/auth.log | tail -20
#1710766549
ip route
#1710766751
ps -ef
#1710775846
echo $SHELL
#1710775859
grep -i 'session opened' /var/log/auth.log | tail -10
#1710776156
lsmod | head
#1710776295
journalctl -xe --no-pager | tail -20
#1710776382
iostat -x 1 3
#1710776514
systemctl status sshd
#1710776577
du -sh /var/log
