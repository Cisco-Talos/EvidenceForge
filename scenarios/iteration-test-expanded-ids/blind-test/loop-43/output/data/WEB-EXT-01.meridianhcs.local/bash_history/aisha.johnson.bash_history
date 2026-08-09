#1710765204
last -20
#1710765680
journalctl -u sshd --since '2 hours ago' --no-pager | tail -30
#1710765703
grep -i 'failed password' /var/log/auth.log | tail -20
#1710765799
pwd
#1710765834
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710769358
who -a
#1710769583
tail -20 /var/log/auth.log
#1710769647
grep -i 'session opened' /var/log/auth.log | tail -20
#1710769786
ps -ef | head
#1710769854
loginctl session-status
#1710769913
cat /proc/sys/kernel/osrelease
#1710772908
systemctl status systemd-resolved --no-pager
#1710773109
journalctl -u php-fpm -n 50 --no-pager
#1710773188
ls -ld /var/log
#1710773213
stat /etc/passwd
#1710773815
mount | column -t
#1710773896
journalctl -u apache2 --since '30 min ago' --no-pager | tail -20
#1710773920
journalctl --since '10 min ago' --no-pager -n 20
#1710774136
cd -
#1710777383
systemctl is-active apache2
#1710777783
journalctl -u systemd-resolved -n 100 --no-pager
#1710777791
ps aux | grep php-fpm
#1710777813
systemctl cat php-fpm 2>/dev/null | head -40
#1710782882
systemctl is-active php-fpm
#1710783281
journalctl -u sshd --since '30 min ago' --no-pager | tail -50
#1710783520
ss -ltnp | grep php-fpm
#1710783931
systemctl cat apache2 2>/dev/null | head -40
#1710784159
cat /etc/crontab
#1710784166
udevadm info --query=property --name=/dev/null | head
#1710784437
ls -lah /tmp | head
