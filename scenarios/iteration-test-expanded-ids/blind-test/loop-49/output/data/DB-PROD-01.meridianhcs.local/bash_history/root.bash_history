#1710782114
pwd
#1710782122
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782137
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782164
df -h /tmp
#1710782231
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782282
du -h /tmp/rpt_0318.sql
#1710782292
file /tmp/rpt_0318.sql
#1710782415
gzip -9 /tmp/rpt_0318.sql
#1710782452
sha256sum /tmp/rpt_0318.sql.gz | cut -c1-16
#1710782545
ls -lh /tmp/rpt_0318.sql.gz
#1710782557
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
