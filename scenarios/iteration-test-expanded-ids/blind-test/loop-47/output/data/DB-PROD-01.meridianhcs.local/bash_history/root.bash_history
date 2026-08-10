#1710782079
pwd
#1710782094
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782112
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782139
df -h /tmp
#1710782218
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782267
ls -lh /tmp/rpt_0318.sql
#1710782280
du -h /tmp/rpt_0318.sql
#1710782341
gzip -9 /tmp/rpt_0318.sql
#1710782365
stat -c '%n %s %y' /tmp/rpt_0318.sql.gz
#1710782391
ls -lh /tmp/rpt_0318.sql.gz
#1710782474
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
