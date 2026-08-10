#1710763944
cat /proc/version | cut -d' ' -f1-3
#1710764321
cat /etc/crontab
#1710765188
dmesg | tail -30
#1710765278
du -sh /home/* 2>/dev/null | head
#1710765590
systemctl is-active postfix
#1710765922
journalctl -u imaps -n 100 --no-pager
#1710765953
ps aux | grep systemd-resolved
#1710766207
systemctl show systemd-resolved -p ActiveState -p SubState -p MainPID
#1710766300
htop
#1710768905
systemctl is-active systemd-resolved
#1710769224
journalctl -u smtp -n 100 --no-pager
#1710769235
ss -ltnp | grep postfix
#1710769515
systemctl show imaps -p ActiveState -p SubState -p MainPID
#1710778127
hostname -f
#1710778410
ls -lah
#1710778931
ps -ef | head
#1710784006
ss -ltnp | grep imaps
#1710784047
loginctl session-status
#1710784496
cat /proc/version | cut -d' ' -f1-3
