#1710779710
systemctl is-active dovecot
#1710779718
journalctl -u smtp -n 100 --no-pager
#1710779793
ss -ltnp | grep dovecot
#1710780137
systemctl show postfix -p ActiveState -p SubState -p MainPID
#1710780145
env | head -20
#1710780191
cd /tmp
#1710780255
exit
#1710780495
ls -ltr /var/log/ | tail -10
