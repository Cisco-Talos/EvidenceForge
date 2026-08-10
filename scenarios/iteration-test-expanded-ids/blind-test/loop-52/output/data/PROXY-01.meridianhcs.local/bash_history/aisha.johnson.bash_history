#1710763229
lsblk
#1710782131
systemctl is-active squid
#1710782183
journalctl -u squid --since '30 min ago' --no-pager | tail -20
#1710782259
ps aux | grep sshd
#1710783468
systemctl cat sshd 2>/dev/null | head -40
#1710783498
ls
