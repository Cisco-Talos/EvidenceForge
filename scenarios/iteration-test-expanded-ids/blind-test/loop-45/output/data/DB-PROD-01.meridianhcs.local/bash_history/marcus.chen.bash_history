#1710767938
systemctl status NetworkManager --no-pager
#1710768439
ss -ltnp | grep mysql
#1710768503
netstat -an | grep ESTABLISHED | wc -l
#1710768528
cd /var/log
#1710769734
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710769741
env | head -20
#1710769771
ulimit -n
#1710778883
journalctl --no-pager -n 5
#1710779408
vmstat 1 5
#1710779803
iostat -x 1 3
#1710780126
systemctl status mysql
#1710780219
env | sort | head
#1710780308
resolvectl query company.okta.com
#1710780450
nmcli device show | grep -E 'GENERAL.DEVICE|IP4.ADDRESS|IP4.GATEWAY'
#1710780485
du -sh /var/log/*
#1710780495
cat /proc/version | cut -d' ' -f1-3
