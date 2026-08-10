#1710782106
df -h /tmp
#1710782125
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782158
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782179
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782226
du -h /tmp/rpt_0318.sql
#1710782551
file /tmp/rpt_0318.sql
#1710782561
gzip -9 /tmp/rpt_0318.sql
#1710782591
ls -lh /tmp/rpt_0318.sql.gz
#1710782629
sha256sum /tmp/rpt_0318.sql.gz | cut -c1-16
#1710782705
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
