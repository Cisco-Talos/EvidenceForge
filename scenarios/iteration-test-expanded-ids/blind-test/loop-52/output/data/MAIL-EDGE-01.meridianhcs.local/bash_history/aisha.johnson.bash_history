#1710764116
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710773826
cd /var/log
#1710774054
env | sort | head
#1710774097
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710778448
who -a
#1710779282
tail -200 /var/log/auth.log
#1710779537
grep -i 'failed password' /var/log/auth.log | tail -20
