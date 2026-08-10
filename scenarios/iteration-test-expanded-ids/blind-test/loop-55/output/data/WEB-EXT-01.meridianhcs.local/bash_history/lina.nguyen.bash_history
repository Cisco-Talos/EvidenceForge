#1710770182
timedatectl
#1710770231
ss -s
#1710770387
curl -s -o /dev/null -w '%{http_code}' http://localhost
#1710770414
tail -200 /var/log/apache2/error.log
#1710773996
free -h
#1710777775
ls -ltr
#1710778231
wc -l /var/log/apache2/access.log
#1710778304
certbot certificates
#1710778348
nginx -t
#1710778389
systemctl reload nginx
#1710778665
curl -sI https://localhost
#1710778692
systemctl reload apache2
#1710778761
id
#1710778843
stat /etc/passwd
#1710778932
journalctl -xe --no-pager | tail -20
#1710779062
ab -n 100 -c 10 http://localhost/
