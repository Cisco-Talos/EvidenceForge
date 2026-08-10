#1710763320
cat /etc/issue
#1710763568
psql -c 'SELECT datname, numbackends FROM pg_stat_database'
#1710771569
python3 --version
#1710771627
find . -name '*.csv' -o -name '*.xlsx' | head
#1710771824
head -5 data.csv 2>/dev/null
#1710777350
hostnamectl
#1710777509
df -h /
#1710778207
ls
#1710784459
psql -c 'SELECT count(*) FROM information_schema.tables'
