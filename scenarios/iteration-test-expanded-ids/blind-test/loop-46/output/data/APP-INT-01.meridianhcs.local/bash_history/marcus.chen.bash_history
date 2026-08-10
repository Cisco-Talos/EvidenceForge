#1710768026
systemctl status sshd --no-pager
#1710768144
journalctl -u systemd-resolved -n 100 --no-pager
#1710768443
ss -ltnp | grep gunicorn
#1710768513
systemctl show gunicorn -p ActiveState -p SubState -p MainPID
#1710768582
systemctl status sshd
#1710768660
tail -f /var/log/syslog &
#1710769065
ls
#1710769235
journalctl -u sshd --since '1 hour ago'
#1710769242
ss -s
