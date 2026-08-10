#1710767624
pwd
#1710767987
ls -lah
#1710780276
tail -200 /var/log/auth.log | grep 'Accepted'
#1710780384
lastb -20
#1710780559
ss -tanp | grep ESTAB | head
#1710780821
find /var/tmp -type f -mtime -1 -ls 2>/dev/null | head
#1710780909
sha256sum /bin/bash /usr/bin/sudo /usr/bin/ssh
