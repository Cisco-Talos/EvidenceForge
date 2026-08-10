#1710769721
cat /proc/version | cut -d' ' -f1-3
#1710769792
cat /etc/os-release
#1710769865
grep -i error /var/log/syslog | tail -100
#1710769928
ss -ltnp | grep squid
#1710769954
grep -i 'failed password' /var/log/auth.log | wc -l
#1710770029
htop
#1710770280
ps -ef | head
#1710770636
cat /proc/meminfo | head -5
#1710770675
nmcli device status 2>/dev/null
#1710770698
ss -s
#1710770761
hostname
#1710770982
last -20
#1710771066
grep -i error /var/log/syslog | tail
#1710771093
lsblk
#1710771166
users
#1710771208
who
#1710772479
hostname -f
#1710772946
ls -lah
#1710773357
uptime
#1710773611
du -sh /tmp/*
#1710773681
cat /etc/hostname
#1710773770
file /usr/bin/ls
#1710773848
ps aux --sort=-%mem | head
#1710774067
getent hosts localhost
#1710779291
dmesg --ctime | tail -20
#1710779451
grep -i error /var/log/syslog | tail -100
#1710779524
df -h /
#1710779561
umask
#1710779951
systemctl status NetworkManager --no-pager
#1710780014
cd -
#1710780066
iostat -x 1 3
#1710780075
cat /proc/cpuinfo | grep 'model name' | head -1
#1710780934
ls -ld /var/log
#1710780967
timedatectl
#1710781001
clear
#1710781183
getent passwd $(whoami)
#1710781237
ic
