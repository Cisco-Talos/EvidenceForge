#1710771360
wc -l data.csv 2>/dev/null
#1710776764
python3 -c 'import pandas as pd; print(pd.__version__)'
#1710777056
find . -name '*.csv' -o -name '*.xlsx' | head
#1710777150
head -5 data.csv 2>/dev/null
#1710777375
env | grep -E 'ODBC|PG|MYSQL|SQL' | head
#1710779467
timedatectl
#1710779611
df -h /
#1710782593
psql -c 'SELECT now(), current_database(), current_user'
#1710782712
cat /etc/resolv.conf
