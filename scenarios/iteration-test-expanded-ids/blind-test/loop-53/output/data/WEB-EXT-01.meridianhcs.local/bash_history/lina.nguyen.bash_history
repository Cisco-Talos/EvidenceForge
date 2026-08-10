#1710773188
cat /etc/nginx/sites-enabled/default
#1710773343
curl -sI https://localhost
#1710773364
find /tmp -maxdepth 1 -type f | head
#1710773373
ab -n 100 -c 10 http://localhost/
#1710784147
curl -s -o /dev/null -w '%{http_code}' http://localhost
#1710784301
tail -50 /var/log/nginx/access.log
#1710784308
apachectl configtest
#1710784400
systemctl status nginx --no-pager
