#1710774530
journalctl -u auditd --since today --no-pager | tail -30
#1710774615
lastb -20
#1710774689
ss -tanp | grep ESTAB | head
#1710774828
find /etc -type f -mtime -1 2>/dev/null | head
