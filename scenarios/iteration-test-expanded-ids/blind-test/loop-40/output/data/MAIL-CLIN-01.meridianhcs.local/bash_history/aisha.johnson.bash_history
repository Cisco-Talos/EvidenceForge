#1710763509
journalctl -u postfix --since '30 min ago' --no-pager | tail -50
#1710763573
ps aux | grep dovecot
#1710763939
systemctl show dovecot -p ActiveState -p SubState -p MainPID
#1710763972
htop
#1710765928
systemctl status smtp --no-pager
#1710766340
journalctl -u postfix --since '30 min ago' --no-pager | tail -200
#1710766572
ps aux | grep imaps
#1710766645
systemctl cat postfix 2>/dev/null | head -40
#1710768701
pwd
#1710768823
ls -ltr
#1710769386
uptime
#1710769396
last -20
#1710769698
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710778577
tail -200 /var/log/auth.log
#1710778630
cat /proc/meminfo | head -5
#1710780101
grep -i 'failed password' /var/log/auth.log | wc -l
#1710780486
nmcli connection show --active
#1710780516
ss -tulnp
#1710783246
cat /proc/version | cut -d' ' -f1-3
#1710783506
apt list --upgradable 2>/dev/null
#1710783555
cat /etc/fstab
#1710783649
du -sh /tmp/*
#1710783736
nmcli device status 2>/dev/null
