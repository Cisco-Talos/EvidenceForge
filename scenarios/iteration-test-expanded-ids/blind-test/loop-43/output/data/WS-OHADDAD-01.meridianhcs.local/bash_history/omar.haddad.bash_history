#1710771875
python3 -c 'import pandas as pd; print(pd.__version__)'
#1710771998
ls -lh ~/Downloads 2>/dev/null | head
#1710772234
head -5 data.csv 2>/dev/null
#1710772323
env | grep -E 'ODBC|PG|MYSQL|SQL' | head
#1710777388
python3 --version
#1710777558
find . -name '*.csv' -o -name '*.xlsx' | head
#1710780067
stat /etc/passwd
#1710782566
wc -l data.csv 2>/dev/null
#1710782737
psql -c 'SELECT now(), current_database(), current_user'
#1710783024
grep -i warning /var/log/syslog | tail
#1710783141
psql -c '\dt'
