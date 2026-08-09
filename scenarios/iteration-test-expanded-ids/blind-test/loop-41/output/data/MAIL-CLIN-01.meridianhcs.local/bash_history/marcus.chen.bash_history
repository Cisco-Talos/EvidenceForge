#1710772614
netstat -an | grep ESTABLISHED | wc -l
#1710772898
journalctl -u postfix -n 50
#1710772953
users
#1710772963
udevadm info --query=property --name=/dev/null | head
#1710773055
uname -a
#1710773096
top -bn1 | head -20
#1710773366
grep -i error /var/log/syslog | tail -200
#1710773523
last -20
#1710773601
ip -o addr show scope global
