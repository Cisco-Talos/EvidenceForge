#1710782118
id
#1710782132
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782157
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782179
df -h /tmp
#1710782406
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782452
du -h /tmp/rpt_0318.sql
#1710782814
ls -lh /tmp/rpt_0318.sql
#1710783234
gzip -9 /tmp/rpt_0318.sql
#1710783276
du -h /tmp/rpt_0318.sql.gz
#1710783458
stat -c '%n %s %y' /tmp/rpt_0318.sql.gz
#1710783551
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
