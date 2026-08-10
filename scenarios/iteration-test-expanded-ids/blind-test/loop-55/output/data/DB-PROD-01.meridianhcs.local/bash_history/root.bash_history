#1710782104
id
#1710782115
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782133
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782156
df -h /tmp
#1710782207
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782257
file /tmp/rpt_0318.sql
#1710782625
ls -lh /tmp/rpt_0318.sql
#1710782633
gzip -9 /tmp/rpt_0318.sql
#1710782665
ls -lh /tmp/rpt_0318.sql.gz
#1710782707
sha256sum /tmp/rpt_0318.sql.gz | cut -c1-16
#1710782783
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
