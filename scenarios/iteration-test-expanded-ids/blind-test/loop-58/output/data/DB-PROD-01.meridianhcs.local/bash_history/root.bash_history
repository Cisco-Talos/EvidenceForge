#1710782080
hostname -f
#1710782090
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782121
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782143
df -h /tmp
#1710782390
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782435
du -h /tmp/rpt_0318.sql
#1710782635
file /tmp/rpt_0318.sql
#1710782665
gzip -9 /tmp/rpt_0318.sql
#1710782693
sha256sum /tmp/rpt_0318.sql.gz | cut -c1-16
#1710782786
du -h /tmp/rpt_0318.sql.gz
#1710782996
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
