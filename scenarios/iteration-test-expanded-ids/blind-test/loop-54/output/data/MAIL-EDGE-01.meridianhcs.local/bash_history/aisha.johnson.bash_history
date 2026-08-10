#1710767871
systemctl status dovecot --no-pager
#1710768122
journalctl -u imaps --since '30 min ago' --no-pager | tail -100
#1710769150
ps aux | grep postfix
#1710769513
systemctl cat imaps 2>/dev/null | head -40
#1710773257
crontab -l
#1710774957
w
#1710775111
journalctl -u imaps -n 20
#1710784328
ps aux | grep dovecot
#1710784413
df -h /
