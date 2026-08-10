#1710763507
ab -n 100 -c 10 http://localhost/
#1710771129
curl -s -o /dev/null -w '%{http_code}' http://localhost
#1710771619
tail -50 /var/log/nginx/access.log
#1710772018
nginx -t
#1710772145
systemctl reload nginx
#1710772154
systemctl reload apache2
#1710772174
uptime
#1710772229
ulimit -n
#1710772542
tail -20 /var/log/nginx/error.log
#1710772618
ls -ltr /var/log/ | tail -10
#1710773172
apachectl configtest
#1710773236
openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -dates
#1710773440
cat /etc/os-release
#1710773512
cat /etc/passwd | head
#1710773576
ps aux | grep systemd-resolved
#1710773618
free -m
#1710773643
python3 -V 2>&1
#1710773702
last -5
#1710773712
ls -la /var/www/html/
#1710784403
tail -200 /var/log/apache2/error.log
#1710784720
systemctl status nginx --no-pager
#1710784788
ab -n 100 -c 10 http://localhost/
