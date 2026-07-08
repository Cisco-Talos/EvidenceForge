#1710765815
systemctl is-active smtp
#1710765826
journalctl -u smtp -n 50 --no-pager
#1710766122
ps aux | grep smtp
#1710766346
systemctl show systemd-resolved -p ActiveState -p SubState -p MainPID
#1710766414
top -bn1 | head -20
#1710766449
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710766456
ls /tmp
#1710766835
iptables -L -n
#1710772666
systemctl is-active imaps
#1710773393
journalctl -u imaps -n 100 --no-pager
#1710773450
ss -ltnp | grep systemd-resolved
#1710773504
systemctl cat systemd-resolved 2>/dev/null | head -40
#1710773513
systemctl status systemd-resolved
