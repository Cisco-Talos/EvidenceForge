#1710765221
python3 --version
#1710765443
ls -lh ~/Downloads 2>/dev/null | head
#1710765626
wc -l data.csv 2>/dev/null
#1710772078
psql -c 'SELECT now(), current_database(), current_user'
#1710779590
python3 -c 'import pandas as pd; print(pd.__version__)'
#1710779832
find . -name '*.csv' -o -name '*.xlsx' | head
#1710780192
head -5 data.csv 2>/dev/null
#1710782037
env | grep -E 'ODBC|PG|MYSQL|SQL' | head
#1710782238
python3 -m pip show sqlalchemy
