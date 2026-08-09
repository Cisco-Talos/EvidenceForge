#1710767343
systemctl is-active squid
#1710767356
journalctl -u sshd --since '30 min ago' --no-pager | tail -50
#1710776178
timedatectl
#1710776190
df -h /
#1710776620
systemctl --failed --no-pager
