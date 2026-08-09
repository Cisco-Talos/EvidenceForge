#1710782086
df -h /tmp
#1710782106
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782126
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782143
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782190
du -h /tmp/rpt_0318.sql
#1710782322
ls -lh /tmp/rpt_0318.sql
#1710782332
gzip -9 /tmp/rpt_0318.sql
#1710782365
ls -lh /tmp/rpt_0318.sql.gz
#1710783654
du -h /tmp/rpt_0318.sql.gz
#1710783664
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
