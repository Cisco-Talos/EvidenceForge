#1710780942
systemctl is-active squid
#1710780995
journalctl -u squid -n 100 --no-pager
#1710781003
systemctl status squid --no-pager
#1710781028
journalctl -u sshd --since '30 min ago' --no-pager | tail -100
#1710781276
ss -ltnp | grep sshd
