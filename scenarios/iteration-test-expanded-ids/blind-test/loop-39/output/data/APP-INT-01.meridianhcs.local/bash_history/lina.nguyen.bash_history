#1710781880
ss -s
#1710781891
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710782108
last -5
#1710782190
tail -20 /var/log/syslog
#1710782284
journalctl --no-pager -n 5
#1710782298
git status --short
#1710782440
loginctl user-status
#1710782852
cd /tmp
#1710783189
git branch -a
#1710783205
git diff --name-only
