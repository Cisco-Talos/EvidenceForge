#1710773095
pwd
#1710773111
ls -lh
#1710773476
uptime
#1710773543
cat /etc/issue
#1710779091
curl -sI https://localhost
#1710779116
tail -200 /var/log/apache2/error.log
#1710779448
nginx -t
#1710779478
systemctl status nginx --no-pager
#1710779702
openssl s_client -connect localhost:443 </dev/null 2>/dev/null | openssl x509 -noout -dates
#1710779996
ls -ltr /var/log/ | tail -10
#1710780060
env | sort | head
