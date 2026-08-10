#1710764142
systemctl status sshd
#1710764309
ss -tan | head
#1710764369
stat /etc/passwd
#1710764450
ulimit -n
#1710764502
journalctl -u NetworkManager --since '2 hours ago' --no-pager | tail -30
#1710764767
tail -20 ~/.bash_history
#1710764776
tail -f /var/log/syslog &
#1710764816
who
#1710764824
resolvectl query company.okta.com
#1710764853
journalctl -u sshd --since '1 hour ago'
#1710765179
journalctl -p err --no-pager -n 10
#1710765245
lsblk
#1710765628
journalctl --no-pager -n 5
#1710765702
history | tail -15
#1710765716
timedatectl
#1710778946
ip -br addr
#1710779265
ip route get 8.8.8.8
#1710780440
tail -50 /var/log/syslog
#1710784347
cat /etc/fstab
