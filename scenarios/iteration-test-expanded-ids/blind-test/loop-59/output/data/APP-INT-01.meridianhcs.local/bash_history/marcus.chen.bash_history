#1710768368
df -h /
#1710768387
grep -i 'failed password' /var/log/auth.log | wc -l
#1710768756
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710768836
journalctl -u sshd --since '1 hour ago'
#1710768902
tail -20 /var/log/syslog
#1710768975
vmstat 1 5
#1710768987
command -v python3
#1710769048
ls -ltr /var/log/ | tail -10
#1710769192
du -sh /home/* 2>/dev/null | head
#1710769224
du -sh /tmp/*
#1710769293
tail -200 /var/log/auth.log
#1710779542
grep -m1 'model name' /proc/cpuinfo
#1710779807
date
#1710779894
udevadm info --query=property --name=/dev/null | head
#1710779901
systemctl list-units --failed
#1710780246
systemctl restart gunicorn
#1710780268
umask
#1710780330
iostat -x 1 3
#1710780370
ss -tulnp
#1710780447
locale
#1710780454
crontab -l
#1710780792
nmcli device status 2>/dev/null
#1710781029
dmesg --ctime | tail -20
#1710781302
ss -ltnp | grep sshd
#1710781316
ss -s
