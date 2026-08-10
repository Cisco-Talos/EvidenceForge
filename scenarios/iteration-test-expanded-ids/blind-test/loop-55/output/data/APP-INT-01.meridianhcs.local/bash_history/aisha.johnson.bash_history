#1710775350
umask
#1710775359
ss -s
#1710775480
cd ~
#1710775566
ss -ltnp | grep sshd
#1710775575
grep -i error /var/log/syslog | tail
#1710775652
id
#1710782869
cat /etc/resolv.conf
#1710782876
env | head -20
#1710783038
file /usr/bin/ls
