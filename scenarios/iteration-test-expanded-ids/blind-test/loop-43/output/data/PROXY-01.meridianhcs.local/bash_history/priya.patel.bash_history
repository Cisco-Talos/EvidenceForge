#1710769378
journalctl -u auditd --since today --no-pager | tail -30
#1710769995
grep -i 'invalid user' /var/log/auth.log | tail -20
#1710770030
ss -tanp | grep ESTAB | head
#1710777276
tail -20 /var/log/auth.log | grep 'Accepted'
#1710782946
journalctl --since '10 min ago' --no-pager -n 20
#1710783032
awk -F: '$3 >= 1000 {print $1}' /etc/passwd
#1710783113
fail2ban-client status
