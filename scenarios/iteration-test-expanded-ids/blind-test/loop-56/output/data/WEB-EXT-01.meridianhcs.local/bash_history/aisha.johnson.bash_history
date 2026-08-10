#1710775586
systemctl status systemd-resolved --no-pager
#1710775601
journalctl -u php-fpm -n 50 --no-pager
#1710775669
ss -ltnp | grep sshd
#1710775956
systemctl cat sshd 2>/dev/null | head -40
#1710780133
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710780530
journalctl -u apache2 -n 100
#1710780590
ls -ld /var/log
#1710780791
ulimit -n
#1710780798
loginctl session-status
