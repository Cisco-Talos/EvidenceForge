#1710763245
cat /proc/sys/kernel/osrelease
#1710763627
curl -sI https://localhost
#1710763738
tail -100 /var/log/apache2/error.log
#1710764159
apachectl configtest
#1710764224
systemctl reload nginx
#1710764657
loginctl list-sessions
#1710764721
cd -
#1710764733
hostname -f
#1710764821
curl -s -o /dev/null -w '%{http_code}' http://localhost
#1710764840
tail -f /var/log/apache2/error.log &
#1710764853
ip route get 8.8.8.8
#1710778632
free -h
#1710778718
systemctl --failed --no-pager
#1710778810
cat /etc/apache2/sites-enabled/000-default.conf
#1710779089
ab -n 100 -c 10 http://localhost/
#1710779447
cat /etc/issue
#1710779456
grep -i failed /var/log/auth.log | tail
#1710779498
curl -s http://localhost/health
#1710779531
openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -dates
#1710780467
journalctl -p err --no-pager -n 10
#1710780476
cat /proc/cpuinfo | grep 'model name' | head -1
#1710780703
tail -200 /var/log/nginx/error.log
