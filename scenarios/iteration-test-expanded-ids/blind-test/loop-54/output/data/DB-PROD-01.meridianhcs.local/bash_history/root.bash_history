#1710782080
hostname -f
#1710782088
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW DATABASES'
#1710782109
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM ehr'
#1710782131
df -h /tmp
#1710782225
mysqldump --single-transaction ehr patients insurance_claims > /tmp/rpt_0318.sql
#1710782271
du -h /tmp/rpt_0318.sql
#1710782366
file /tmp/rpt_0318.sql
#1710783058
gzip -9 /tmp/rpt_0318.sql
#1710783086
stat -c '%n %s %y' /tmp/rpt_0318.sql.gz
#1710783122
ls -lh /tmp/rpt_0318.sql.gz
#1710783163
scp /tmp/rpt_0318.sql.gz root@10.10.2.30:/tmp/.cache/rpt_0318.sql.gz
