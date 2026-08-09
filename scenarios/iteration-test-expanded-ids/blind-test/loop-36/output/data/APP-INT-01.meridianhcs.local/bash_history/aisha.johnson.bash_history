#1710776940
tail -100 /var/log/auth.log
#1710777065
grep -i 'failed password' /var/log/auth.log | tail -20
#1710777212
cat /etc/os-release
