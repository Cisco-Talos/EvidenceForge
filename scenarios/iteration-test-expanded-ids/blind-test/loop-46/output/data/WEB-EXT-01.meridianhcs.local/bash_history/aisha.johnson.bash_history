#1710765600
timedatectl
#1710765778
ss -s
#1710768414
systemctl status apache2 --no-pager
#1710768486
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -100
#1710768570
ss -ltnp | grep php-fpm
#1710768582
systemctl cat sshd 2>/dev/null | head -40
#1710768618
systemctl restart sshd
#1710770183
ss -tulnp
#1710770256
grep -i error /var/log/syslog | tail -200
#1710778389
systemctl status php-fpm --no-pager
#1710778453
journalctl -u systemd-resolved -n 100 --no-pager
#1710778508
ss -ltnp | grep apache2
#1710778520
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710778828
cat /etc/fstab
