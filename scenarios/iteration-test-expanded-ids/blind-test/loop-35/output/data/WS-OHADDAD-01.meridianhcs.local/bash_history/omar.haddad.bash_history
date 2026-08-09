#1710764265
mysql --defaults-extra-file=~/.my.cnf -e 'SELECT COUNT(*) FROM production.users'
#1710764281
journalctl -xe --no-pager | tail -20
#1710768470
systemctl list-timers --all --no-pager | head
#1710772856
python3 --version
#1710772926
find . -name '*.csv' -o -name '*.xlsx' | head
#1710775664
getent passwd $(whoami)
#1710775870
jupyter --paths 2>/dev/null | head
#1710779417
ss -s
#1710779614
ls -ltr /var/log | tail
#1710779889
ls -ld /var/log
#1710780316
ls /var/log
#1710781493
wc -l data.csv 2>/dev/null
