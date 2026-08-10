#1710771639
systemd-analyze blame | head
#1710771657
grep -i warning /var/log/syslog | tail
#1710771751
resolvectl query login.microsoftonline.com
#1710771785
du -sh /tmp/*
#1710772123
lsmod | head
#1710772174
journalctl -u postfix -n 100
#1710772354
ip -o addr show scope global
#1710772395
groups
#1710772610
apt list --upgradable 2>/dev/null
#1710772667
locale
#1710772732
env | sort | head
#1710772804
iostat -x 1 3
#1710772882
htop
#1710773102
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710773551
whoami
#1710773862
ls -lh
#1710773969
uptime
#1710776201
systemctl is-active systemd-resolved
#1710777517
journalctl -u postfix -n 20 --no-pager
#1710777550
ps aux | grep dovecot
#1710777571
systemctl show smtp -p ActiveState -p SubState -p MainPID
#1710777612
journalctl -u systemd-resolved --since '30 min ago' --no-pager | tail -20
#1710777676
systemctl restart postfix
#1710777689
ps aux
#1710777761
lsmod | head
#1710777934
journalctl -u dovecot -n 100
