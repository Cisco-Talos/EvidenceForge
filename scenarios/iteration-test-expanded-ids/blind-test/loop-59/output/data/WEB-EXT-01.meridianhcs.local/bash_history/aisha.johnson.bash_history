#1710765461
last -20
#1710765508
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710765750
grep -i 'session opened' /var/log/auth.log | tail -20
#1710766135
grep -i 'session opened' /var/log/auth.log | tail -10
#1710769211
tail -50 /var/log/auth.log
#1710769522
grep -i 'failed password' /var/log/auth.log | tail -20
#1710769773
ls -ltr /var/log | tail
#1710770131
grep -i 'failed password' /var/log/auth.log | wc -l
#1710770450
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710770486
cat /etc/fstab
#1710780480
tail -200 /var/log/syslog
#1710780545
ps -ef | head
#1710780614
systemctl status NetworkManager --no-pager
#1710780627
systemctl list-timers --all --no-pager | head
