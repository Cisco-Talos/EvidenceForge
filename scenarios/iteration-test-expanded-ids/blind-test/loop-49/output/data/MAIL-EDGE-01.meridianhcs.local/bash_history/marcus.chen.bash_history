#1710770145
du -sh /var/log
#1710770273
stat /etc/passwd
#1710777429
systemctl status dovecot --no-pager
#1710777547
journalctl -u postfix --since '30 min ago' --no-pager | tail -200
#1710780464
hostnamectl
#1710781834
tail -50 /var/log/auth.log
#1710782845
tail -100 /var/log/auth.log
#1710782977
systemctl list-timers
#1710783163
htop
#1710783170
iptables -L -n
#1710783243
ss -tulnp
#1710783313
systemctl status postfix
#1710783349
crontab -l
