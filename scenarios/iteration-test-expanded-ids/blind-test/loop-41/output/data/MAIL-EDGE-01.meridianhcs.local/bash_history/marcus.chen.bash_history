#1710765829
systemctl status dovecot --no-pager
#1710765840
journalctl -u smtp -n 50 --no-pager
#1710766164
ps aux | grep dovecot
#1710766327
systemctl show imaps -p ActiveState -p SubState -p MainPID
#1710766496
ls -lah /tmp | head
#1710766503
grep -i error /var/log/syslog | tail
#1710766557
cat /etc/passwd | head
#1710766772
tail -20 ~/.bash_history
#1710766849
resolvectl status 2>/dev/null | head -30
#1710766917
cat /proc/cpuinfo | grep 'model name' | head -1
#1710766964
htop
#1710780318
journalctl -u sshd --since '1 hour ago'
#1710780571
ss -tulnp
#1710780846
cd /var/log
#1710781173
cat /etc/hostname
#1710781279
whoami
#1710781325
env | sort | head
#1710781413
grep -i 'session opened' /var/log/auth.log | tail -10
#1710781498
resolvectl query company.okta.com
#1710781574
find /etc/systemd/user -maxdepth 2 -type f 2>/dev/null | head
#1710783620
systemctl status postfix --no-pager
#1710783675
journalctl -u smtp --since '30 min ago' --no-pager | tail -200
#1710783894
ps aux | grep smtp
#1710784028
systemctl show smtp -p ActiveState -p SubState -p MainPID
#1710784546
resolvectl query login.microsoftonline.com
#1710784583
udevadm info --query=property --name=/dev/null | head
