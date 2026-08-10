#1710766633
systemctl is-active systemd-resolved
#1710766711
journalctl -u smtp -n 100 --no-pager
#1710766722
ps aux | grep dovecot
#1710767082
systemctl show dovecot -p ActiveState -p SubState -p MainPID
#1710767363
hostname
#1710775065
who -a
#1710775463
tail -100 /var/log/auth.log
#1710778800
locale
#1710779389
tail -20 ~/.bash_history
#1710781840
cd -
