#1710765435
journalctl -u systemd-resolved -n 200
#1710765453
systemctl list-timers --all --no-pager | head
#1710765669
python3 -V 2>&1
#1710765716
lsblk
#1710765764
iostat -x 1 3
#1710765792
df -h
#1710765854
timedatectl
#1710765904
cd ~
#1710765961
grep -i 'failed password' /var/log/auth.log | wc -l
#1710769940
hostname -f
#1710772642
systemctl is-active squid
#1710772946
journalctl -u squid -n 50 --no-pager
#1710773041
ps aux | grep sshd
#1710773368
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710773432
uname -sr
#1710773463
cat /proc/cpuinfo | grep 'model name' | head -1
#1710773834
journalctl -u sshd --since '30 min ago' --no-pager | tail -20
#1710773858
users
#1710774275
systemctl status NetworkManager --no-pager
#1710774307
df -h /tmp
#1710774913
cat /etc/hostname
#1710776107
tail -100 /var/log/auth.log
#1710776269
grep -i 'failed password' /var/log/auth.log | tail -20
#1710776684
date -u
#1710776695
tail -20 ~/.bash_history
#1710776743
journalctl -u squid -n 200
#1710776754
ls /var/log
#1710776832
exit
#1710777201
cd -
#1710777211
systemctl list-timers --all --no-pager | head
#1710777289
tail -50 /var/log/auth.log
#1710777298
grep -i error /var/log/syslog | tail -200
#1710777379
nmcli connection show --active
#1710777385
df -h /var
#1710777480
file /usr/bin/ls
#1710777491
du -sh /tmp/*
#1710782032
systemctl restart squid
#1710782045
ulimit -n
#1710782072
systemctl status systemd-resolved
#1710782522
getent passwd $(whoami)
#1710782611
stat /etc/passwd
#1710782621
ls -lh
#1710782644
loginctl user-status
#1710783014
ls
#1710783027
last -20
#1710783271
ls -la
#1710783330
udevadm info --query=property --name=/dev/null | head
#1710783687
journalctl -u squid -n 50
#1710784093
cat /etc/hostname
#1710784255
find /var/log -name '*.gz' -mtime +30 | wc -l
#1710784267
journalctl -u sshd -n 200
#1710784774
systemctl status squid --no-pager
