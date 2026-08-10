#1710782091
pwd
#1710782098
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782121
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782140
df -h /tmp
#1710782213
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782258
ls -lh /tmp/rpt_0318.sql
#1710782271
du -h /tmp/rpt_0318.sql
#1710782328
gzip -9 /tmp/rpt_0318.sql
#1710782361
du -h /tmp/rpt_0318.sql.gz
#1710782424
stat -c '%n %s %y' /tmp/rpt_0318.sql.gz
#1710782516
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
