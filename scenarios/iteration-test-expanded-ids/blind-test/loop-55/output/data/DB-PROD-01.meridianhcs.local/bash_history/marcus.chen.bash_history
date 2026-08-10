#1710763816
systemctl is-active mysql
#1710764068
journalctl -u mysql --since '30 min ago' --no-pager | tail -200
#1710764905
ps aux | grep mysql
#1710764944
systemctl cat mysql 2>/dev/null | head -40
#1710764955
journalctl -u mysql -n 50
#1710765197
sysctl -a 2>/dev/null | grep net.ipv4.ip_forward
#1710765206
ls -lt /var/log | head
#1710765250
id
#1710765785
ps aux
#1710765811
yum check-update 2>/dev/null
#1710765871
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710765960
crontab -l
#1710765993
ls -ltr /var/log | tail
#1710766128
journalctl -u sshd -n 100
#1710766148
dnf check-update 2>/dev/null
#1710770311
timedatectl
#1710773514
systemctl status mysql --no-pager
#1710773857
journalctl -u mysql -n 100 --no-pager
