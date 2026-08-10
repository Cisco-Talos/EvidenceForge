#1710763832
uptime
#1710764164
free -h
#1710765171
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710765266
systemctl --failed --no-pager
#1710765298
who -a
#1710765589
cd ~
#1710765624
ip route
#1710765874
mount | column -t
#1710766095
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710766163
systemctl is-active postfix
#1710766317
journalctl -u smtp -n 50 --no-pager
#1710766592
ps aux | grep smtp
#1710766684
systemctl show systemd-resolved -p ActiveState -p SubState -p MainPID
#1710766733
journalctl -u sshd --since '1 hour ago'
#1710766775
ip -br addr
#1710773017
tail -50 /var/log/auth.log
#1710773045
grep -i 'session opened' /var/log/auth.log | tail -20
#1710773111
htop
#1710773272
python3 -V 2>&1
#1710773319
uname -a
#1710773327
env | head -20
#1710773419
tail -100 /var/log/syslog
#1710773586
journalctl --no-pager -n 5
#1710783653
grep -i 'session opened' /var/log/auth.log | tail -10
#1710783891
llsmod
#1710783932
journalctl --since '10 min ago' --no-pager -n 20
#1710783998
vmstat 1 5
#1710784556
crontab -l
#1710784737
dmesg --ctime | tail -20
