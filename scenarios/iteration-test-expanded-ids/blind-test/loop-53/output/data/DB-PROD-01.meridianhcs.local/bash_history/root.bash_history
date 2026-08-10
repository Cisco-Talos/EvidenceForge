#1710782067
id
#1710782079
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782098
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782121
df -h /tmp
#1710782163
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782208
du -h /tmp/rpt_0318.sql
#1710782244
file /tmp/rpt_0318.sql
#1710782460
gzip -9 /tmp/rpt_0318.sql
#1710782496
sha256sum /tmp/rpt_0318.sql.gz | cut -c1-16
#1710782507
ls -lh /tmp/rpt_0318.sql.gz
#1710782643
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
