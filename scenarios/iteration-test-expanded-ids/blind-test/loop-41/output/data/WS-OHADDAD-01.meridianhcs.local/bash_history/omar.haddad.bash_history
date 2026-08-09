#1710767859
hostnamectl
#1710768128
free -h
#1710773147
python3 -c 'import pandas as pd; print(pd.__version__)'
#1710773205
find . -name '*.csv' -o -name '*.xlsx' | head
#1710773472
head -5 data.csv 2>/dev/null
#1710773577
env | grep -E 'ODBC|PG|MYSQL|SQL' | head
#1710776235
python3 --version
#1710776295
ls -lh ~/Downloads 2>/dev/null | head
#1710776525
wc -l data.csv 2>/dev/null
#1710776610
psql -c 'SELECT now(), current_database(), current_user'
#1710779951
psql -c 'SELECT count(*) FROM information_schema.tables'
#1710780246
python3 -m pip show pandas
#1710780405
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710780443
mysql --defaults-extra-file=~/.my.cnf -e 'SELECT COUNT(*) FROM production.users'
#1710782009
psql -c '\dt'
#1710782304
du -sh ./data 2>/dev/null
