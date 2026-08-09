#1710782113
df -h /tmp
#1710782126
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782154
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782181
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782229
file /tmp/rpt_0318.sql
#1710782286
du -h /tmp/rpt_0318.sql
#1710782381
gzip -9 /tmp/rpt_0318.sql
#1710782424
ls -lh /tmp/rpt_0318.sql.gz
#1710782491
stat -c '%n %s %y' /tmp/rpt_0318.sql.gz
#1710782521
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
