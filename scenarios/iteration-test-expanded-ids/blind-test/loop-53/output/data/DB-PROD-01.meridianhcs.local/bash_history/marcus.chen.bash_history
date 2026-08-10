#1710783795
systemctl is-active mysql
#1710784076
journalctl -u sshd --since '30 min ago' --no-pager | tail -200
#1710784167
ss -ltnp | grep mysql
#1710784191
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710784320
journalctl -xe --no-pager | tail -20
#1710784416
cd -
#1710784490
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710784714
getent hosts localhost
#1710784760
ls -ltr /var/log | tail
#1710784768
mount | column -t
