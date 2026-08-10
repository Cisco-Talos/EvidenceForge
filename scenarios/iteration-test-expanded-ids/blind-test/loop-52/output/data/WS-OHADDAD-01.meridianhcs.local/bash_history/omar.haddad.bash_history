#1710766179
env | grep -E 'ODBC|PG|MYSQL|SQL' | head
#1710766442
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM analytics'
#1710766579
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710771533
python3 --version
#1710771776
cat /proc/sys/kernel/osrelease
#1710776345
find . -name '*.csv' -o -name '*.xlsx' | head
#1710776567
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710776591
python3 -m pip show pandas
#1710776878
head -5 data.csv 2>/dev/null
#1710780666
free -m
#1710783736
dmesg --ctime | tail -20
#1710783945
grep -R "select .* from" . 2>/dev/null | head
