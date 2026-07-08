#1710767612
hostname -f
#1710767742
ls -lah
#1710771235
python3 -c 'import pandas as pd; print(pd.__version__)'
#1710771401
find . -name '*.csv' -o -name '*.xlsx' | head
#1710774298
wc -l data.csv 2>/dev/null
#1710774602
env | grep -E 'ODBC|PG|MYSQL|SQL' | head
#1710774614
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710774825
echo $SHELL
#1710779142
mysql --defaults-extra-file=~/.my.cnf -e 'SELECT COUNT(*) FROM mydb.users'
#1710779427
loginctl list-sessions
#1710779795
psql -c '\l'
#1710782736
python3 -m pip show pandas
#1710783009
du -sh /home/* 2>/dev/null | head
#1710783346
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710783379
uname -sr
