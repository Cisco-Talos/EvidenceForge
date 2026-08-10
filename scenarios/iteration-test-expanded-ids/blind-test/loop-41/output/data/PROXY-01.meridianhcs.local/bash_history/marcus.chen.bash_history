#1710777476
systemctl status squid --no-pager
#1710781688
systemctl is-active systemd-resolved
#1710781742
journalctl -u sshd --since '30 min ago' --no-pager | tail -20
#1710782105
ss -ltnp | grep systemd-resolved
#1710782190
systemctl show squid -p ActiveState -p SubState -p MainPID
#1710782378
netstat -an | grep ESTABLISHED | wc -l
#1710782714
grep -i 'failed password' /var/log/auth.log | wc -l
#1710782767
systemctl status NetworkManager --no-pager
#1710782830
journalctl -u systemd-resolved -n 100
#1710783897
journalctl -u systemd-resolved --since today --no-pager | tail -20
#1710784627
tail -20 /var/log/auth.log
