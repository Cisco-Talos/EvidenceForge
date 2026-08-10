#1710766240
systemctl is-active mysql
#1710766252
journalctl -u mysql -n 200 --no-pager
#1710766280
ps aux | grep mysql
#1710766479
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710766533
hostnamectl
#1710767758
timedatectl
#1710768851
df -h /
#1710769780
whoami
#1710769850
ls -lah
#1710770263
date
#1710783290
ss -ltnp | grep mysql
#1710783388
cat /etc/hostname
#1710783709
systemctl list-units --failed
