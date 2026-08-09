#1710764373
df -h /tmp
#1710780034
systemctl is-active sshd
#1710780158
journalctl -u sshd -n 100 --no-pager
#1710780403
ps aux | grep sshd
#1710780460
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710783764
cat /etc/fstab
#1710783919
ls -la
#1710783943
free -m
#1710783979
ls -ltr /var/log | tail
