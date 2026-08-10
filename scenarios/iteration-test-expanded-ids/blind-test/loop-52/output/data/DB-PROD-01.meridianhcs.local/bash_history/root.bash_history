#1710782100
pwd
#1710782112
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782126
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782140
df -h /tmp
#1710782219
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782279
du -h /tmp/rpt_0318.sql
#1710782286
ls -lh /tmp/rpt_0318.sql
#1710782347
gzip -9 /tmp/rpt_0318.sql
#1710782380
stat -c '%n %s %y' /tmp/rpt_0318.sql.gz
#1710782387
ls -lh /tmp/rpt_0318.sql.gz
#1710782552
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
