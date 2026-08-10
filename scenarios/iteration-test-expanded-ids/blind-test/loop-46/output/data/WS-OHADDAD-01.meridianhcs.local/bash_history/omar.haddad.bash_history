#1710773377
mysql --defaults-extra-file=~/.my.cnf -e 'SHOW TABLES FROM appdb'
#1710775252
python3 --version
#1710775477
find . -name '*.csv' -o -name '*.xlsx' | head
#1710775513
head -5 data.csv 2>/dev/null
#1710780558
psql -c '\l'
#1710783123
journalctl --since '10 min ago' --no-pager -n 20
#1710783457
mysql --defaults-extra-file=~/.my.cnf -e 'SELECT COUNT(*) FROM production.users'
#1710783475
ls -lh ~/Downloads 2>/dev/null | head
