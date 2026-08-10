#1710767439
uptime
#1710767593
free -h
#1710767757
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710767766
ip route
#1710767925
journalctl -u systemd-resolved -n 20
#1710767933
cat /proc/sys/kernel/osrelease
#1710772218
last -20
#1710772256
tail -200 /var/log/auth.log
#1710772307
grep -i 'failed password' /var/log/auth.log | tail -20
#1710772400
ls /var/log
#1710772709
ss -tan | head
#1710782509
ss -ltnp | grep sshd
#1710782926
ls -ld /var/log
#1710783861
iostat -x 1 3
#1710783930
ip -o addr show scope global
#1710784465
resolvectl query login.microsoftonline.com
