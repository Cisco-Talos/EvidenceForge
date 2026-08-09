#1710768763
cd ~
#1710769037
journalctl -u sshd --since '1 hour ago'
#1710779161
systemctl status systemd-resolved --no-pager
#1710779249
journalctl -u postfix -n 200 --no-pager
