#1710782081
id
#1710782092
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782122
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782145
df -h /tmp
#1710782212
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782266
file /tmp/rpt_0318.sql
#1710782308
ls -lh /tmp/rpt_0318.sql
#1710782333
gzip -9 /tmp/rpt_0318.sql
#1710782362
sha256sum /tmp/rpt_0318.sql.gz | cut -c1-16
#1710782374
stat -c '%n %s %y' /tmp/rpt_0318.sql.gz
#1710782397
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
