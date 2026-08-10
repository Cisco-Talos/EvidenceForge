#1710764007
git status --short
#1710764294
git diff --name-only
#1710764453
cat /etc/issue
#1710765680
git pull origin main
#1710765955
ssh -o ConnectTimeout=10 lina.nguyen@DB-PROD-01.meridianhcs.local
#1710765957
ssh lina.nguyen@10.10.4.10
#1710767073
ssh -i ~/.ssh/id_rsa lina.nguyen@APP-INT-01
#1710768024
ssh -o ServerAliveInterval=30 lina.nguyen@10.10.4.10
#1710768099
ssh lina.nguyen@10.10.2.30
#1710768653
ssh lina.nguyen@WEB-EXT-01.meridianhcs.local
#1710768946
timedatectl
#1710768956
ssh -i ~/.ssh/id_ed25519 lina.nguyen@DB-PROD-01.meridianhcs.local
#1710769183
free -h
#1710769225
journalctl -p warning --since '1 hour ago' --no-pager | tail -20
#1710769600
ssh -i ~/.ssh/work_ed25519 lina.nguyen@DB-PROD-01.meridianhcs.local
#1710769847
ssh -l lina.nguyen 10.10.2.30
#1710771054
git rev-parse --show-toplevel
#1710771086
journalctl -xe --no-pager | tail -20
#1710771700
ssh -o ServerAliveInterval=30 lina.nguyen@WEB-EXT-01
#1710772171
ssh -l lina.nguyen WEB-EXT-01.meridianhcs.local
#1710772330
git log --oneline --graph -15
#1710774112
ssh lina.nguyen@WEB-EXT-01.meridianhcs.local
#1710774835
git diff --stat
#1710774868
npm test
#1710774954
docker logs --tail 50 worker
#1710775357
ssh -i ~/.ssh/id_rsa lina.nguyen@WEB-EXT-01
#1710776878
ssh -tt lina.nguyen@WEB-EXT-01.meridianhcs.local
#1710779469
python3 -m pytest -v
#1710779519
docker compose ps
#1710782370
ls -lh
#1710782531
ssh lina.nguyen@DB-PROD-01
#1710783305
grep -i error /var/log/syslog | tail
#1710784450
ssh -l lina.nguyen WEB-EXT-01.meridianhcs.local
