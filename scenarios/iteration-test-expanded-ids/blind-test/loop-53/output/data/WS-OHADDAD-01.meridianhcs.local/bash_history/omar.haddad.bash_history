#1710763320
cat /etc/issue
#1710763568
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710772425
grep -R "select .* from" . 2>/dev/null | head
#1710774818
python3 -c 'import pandas as pd; print(pd.__version__)'
#1710775045
ls -lh ~/Downloads 2>/dev/null | head
#1710775257
head -5 data.csv 2>/dev/null
#1710780010
cat /etc/passwd | head
#1710783588
psql -c 'SELECT now(), current_database(), current_user'
