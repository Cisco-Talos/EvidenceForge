#1710768623
timedatectl
#1710769053
ss -s
#1710769364
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710769441
ll
#1710769743
file /usr/bin/ls
#1710769785
cat /etc/apache2/sites-enabled/000-default.conf
#1710769855
ps -ef | head
#1710769933
ip route
#1710769961
ip -br addr
#1710770120
curl -s -o /dev/null -w '%{http_code}' http://localhost
#1710770146
cat /etc/nginx/sites-enabled/default
#1710775185
curl -sI https://localhost
#1710775213
tail -20 /var/log/nginx/access.log
#1710775271
apachectl configtest
#1710775283
systemctl reload nginx
#1710775387
exit
#1710775458
cd ~
#1710776510
tail -20 /var/log/nginx/error.log
#1710778649
free -h
#1710778707
echo $SHELL
#1710778831
getent hosts localhost
#1710779280
curl -s http://localhost/health
#1710779308
umask
#1710779387
locale
#1710779398
uptime
