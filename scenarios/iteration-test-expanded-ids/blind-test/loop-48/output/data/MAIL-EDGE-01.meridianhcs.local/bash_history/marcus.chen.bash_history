#1710776245
cd /var/log
#1710776256
ss -tan | head
#1710776771
grep -i 'failed password' /var/log/auth.log | wc -l
#1710776845
df -h /tmp
#1710776852
ls -la
#1710777258
ss -ltnp | grep systemd-resolved
#1710777606
ls -ltr /var/log | tail
#1710777657
systemctl status sshd
#1710777695
cat /proc/version | cut -d' ' -f1-3
#1710777727
journalctl -u postfix -n 200
#1710777771
du -sh /var/log/*
#1710777814
tail -50 /var/log/syslog
#1710784598
pwd
#1710784778
ls -lh
