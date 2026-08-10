#1710768994
cat /etc/apache2/sites-enabled/000-default.conf
#1710769679
loginctl list-sessions
#1710769868
certbot certificates
#1710769952
find /tmp -maxdepth 1 -type f | head
#1710769980
tail -200 /var/log/nginx/error.log
#1710769989
systemctl --failed --no-pager
#1710770146
systemctl reload apache2
#1710770190
curl -s -o /dev/null -w '%{http_code}' http://localhost
#1710770222
curl -sI https://localhost
#1710770252
tail -100 /var/log/nginx/access.log
#1710770393
ss -tan | head
#1710772366
openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -dates
#1710772426
tail -f /var/log/apache2/access.log &
#1710772464
ulimit -n
#1710772644
exit
#1710773031
certbot renew --dry-run
#1710773235
command -v python3
#1710773302
cd /var/log
#1710773359
date -u
#1710773386
wc -l /var/log/apache2/access.log
#1710773508
ls -ld /var/log
#1710779004
apachectl configtest
#1710779308
tail -20 /var/log/syslog
#1710779329
nginx -t
#1710779725
curl -s http://localhost/health
#1710779744
grep -m1 'model name' /proc/cpuinfo
#1710780810
cd -
#1710780862
ls -la /var/www/html/
#1710780926
loginctl user-status
#1710781173
tail -20 /var/log/nginx/error.log
