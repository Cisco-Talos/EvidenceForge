#1710763513
journalctl -u auditd --since today --no-pager | tail -30
#1710763696
lastb -20
#1710763908
ip neigh show
#1710774498
fail2ban-client status sshd
#1710775095
grep -i 'invalid user' /var/log/auth.log | tail -20
#1710775152
getent group docker
#1710775301
ausearch -m avc --start today
#1710782566
hostname
#1710782855
cat /etc/hostname
