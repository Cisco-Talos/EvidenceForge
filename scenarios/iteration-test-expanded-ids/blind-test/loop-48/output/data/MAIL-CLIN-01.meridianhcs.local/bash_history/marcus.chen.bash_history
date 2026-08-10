#1710768250
du -sh /tmp/*
#1710768257
date
#1710768657
systemctl restart smtp
#1710768831
cat /etc/hostname
#1710769525
timedatectl
#1710769751
w
#1710769792
ls -ltr /var/log/ | tail -10
#1710769886
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710770058
cat /etc/passwd | head
#1710770071
dmesg | tail -30
#1710773790
ss -s
#1710773818
systemctl --failed --no-pager
#1710773897
journalctl -u postfix --since '30 min ago' --no-pager | tail -20
#1710778684
ls -lah /tmp | head
#1710778970
who
#1710779163
htop
#1710779211
lsblk
#1710779221
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710779268
cd ~
#1710779275
netstat -an | grep ESTABLISHED | wc -l
#1710779546
ls
#1710779848
vmstat 1 5
#1710780338
systemctl list-units --failed
#1710780399
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710780470
iostat -x 1 3
