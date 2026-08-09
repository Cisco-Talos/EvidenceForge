#1710773828
ss -tulnp
#1710773860
groups
#1710773901
vmstat 1 5
#1710781797
tail -200 /var/log/auth.log
#1710781836
grep -i 'session opened' /var/log/auth.log | tail -20
#1710781893
cat /proc/meminfo | head -5
#1710781930
users
#1710783366
ss -ltnp | grep mysql
#1710783403
systemctl status NetworkManager --no-pager
#1710783911
cat /proc/version | cut -d' ' -f1-3
#1710783983
dnf check-update 2>/dev/null
#1710784041
cd ~
