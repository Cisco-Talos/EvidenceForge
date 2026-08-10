#1710769814
python3 -c 'import pandas as pd; print(pd.__version__)'
#1710769867
find . -name '*.csv' -o -name '*.xlsx' | head
#1710770058
head -5 data.csv 2>/dev/null
#1710772616
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710776889
pwd
#1710777048
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710777127
psql -c 'SELECT now(), current_database(), current_user'
#1710777205
find /tmp -maxdepth 1 -type f | head
#1710780492
last -5
#1710782905
env | grep -E 'ODBC|PG|MYSQL|SQL' | head
#1710783099
ps aux
