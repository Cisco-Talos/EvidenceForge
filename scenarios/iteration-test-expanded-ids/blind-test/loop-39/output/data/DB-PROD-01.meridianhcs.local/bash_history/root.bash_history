#1710782081
pwd
#1710782098
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782124
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782144
df -h /tmp
#1710782228
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782287
ls -lh /tmp/rpt_0318.sql
#1710782489
file /tmp/rpt_0318.sql
#1710782503
gzip -9 /tmp/rpt_0318.sql
#1710782550
du -h /tmp/rpt_0318.sql.gz
#1710782610
ls -lh /tmp/rpt_0318.sql.gz
#1710782704
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
