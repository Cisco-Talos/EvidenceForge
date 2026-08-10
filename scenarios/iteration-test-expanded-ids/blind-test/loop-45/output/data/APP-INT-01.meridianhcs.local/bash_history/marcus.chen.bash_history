#1710770094
systemctl status systemd-resolved --no-pager
#1710770371
journalctl -u gunicorn --since '30 min ago' --no-pager | tail -20
#1710770495
ss -ltnp | grep sshd
#1710772599
systemctl is-active sshd
#1710772689
journalctl -u systemd-resolved -n 200 --no-pager
#1710772851
ss -ltnp | grep gunicorn
#1710772876
systemctl cat systemd-resolved 2>/dev/null | head -40
#1710773062
iptables -L -n
#1710773474
tail -100 /var/log/syslog
#1710773744
stat /etc/passwd
#1710773877
journalctl -u systemd-resolved -n 50
#1710773906
journalctl --since '10 min ago' --no-pager -n 20
#1710782179
systemctl status gunicorn --no-pager
#1710782251
journalctl -u gunicorn -n 20 --no-pager
#1710782503
ps aux | grep systemd-resolved
#1710782513
systemctl show gunicorn -p ActiveState -p SubState -p MainPID
#1710782585
file /usr/bin/ls
#1710782741
cat /proc/meminfo | head -5
#1710782772
systemctl list-units --failed
#1710782837
ps aux | grep gunicorn
