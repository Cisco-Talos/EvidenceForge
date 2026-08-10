#1710782076
hostname -f
#1710782086
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782115
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782132
df -h /tmp
#1710782225
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782282
file /tmp/rpt_0318.sql
#1710782338
du -h /tmp/rpt_0318.sql
#1710782405
gzip -9 /tmp/rpt_0318.sql
#1710782431
du -h /tmp/rpt_0318.sql.gz
#1710782456
sha256sum /tmp/rpt_0318.sql.gz | cut -c1-16
#1710782465
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
