#1710782080
id
#1710782092
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782118
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782145
df -h /tmp
#1710782497
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782546
du -h /tmp/rpt_0318.sql
#1710782559
file /tmp/rpt_0318.sql
#1710782948
gzip -9 /tmp/rpt_0318.sql
#1710782976
du -h /tmp/rpt_0318.sql.gz
#1710783014
ls -lh /tmp/rpt_0318.sql.gz
#1710783044
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
