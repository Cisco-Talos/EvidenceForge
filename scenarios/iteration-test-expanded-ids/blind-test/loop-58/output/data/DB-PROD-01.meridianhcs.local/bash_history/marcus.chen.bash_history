#1710776165
systemctl is-active mysql
#1710776390
journalctl -u sshd --since '30 min ago' --no-pager | tail -100
#1710776415
ss -ltnp | grep mysql
#1710776444
systemctl show sshd -p ActiveState -p SubState -p MainPID
#1710777301
exit
#1710777325
systemctl status mysql
#1710777659
systemctl restart mysql
