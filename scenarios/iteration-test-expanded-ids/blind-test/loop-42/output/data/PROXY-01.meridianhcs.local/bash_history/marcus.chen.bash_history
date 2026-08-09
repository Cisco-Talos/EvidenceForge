#1710773918
id
#1710773939
clear
#1710784111
systemctl status squid --no-pager
#1710784387
journalctl -u sshd --since '30 min ago' --no-pager | tail -50
#1710784475
ps aux | grep sshd
#1710784620
systemctl show squid -p ActiveState -p SubState -p MainPID
#1710784629
ls -ltr /var/log/ | tail -10
