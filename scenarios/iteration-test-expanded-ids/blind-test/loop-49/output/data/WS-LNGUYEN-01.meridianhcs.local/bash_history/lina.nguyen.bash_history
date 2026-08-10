#1710764282
ssh lina.nguyen@WEB-EXT-01.meridianhcs.local
#1710764301
ssh lina.nguyen@DB-PROD-01.meridianhcs.local
#1710764380
ssh -o ConnectTimeout=10 lina.nguyen@WEB-EXT-01.meridianhcs.local
#1710765552
git status --short
#1710765825
git diff --stat
#1710766494
ssh -l lina.nguyen WEB-EXT-01.meridianhcs.local
#1710768001
ssh -o ServerAliveInterval=30 lina.nguyen@10.10.3.10
#1710768129
ssh lina.nguyen@WEB-EXT-01.meridianhcs.local
#1710768660
git diff --name-only
#1710771214
ssh lina.nguyen@WEB-EXT-01
#1710771763
git pull origin release/v2.4
#1710771799
emacs -nw /home/lina.nguyen/src/monitoring/index.js
#1710772776
ssh lina.nguyen@DB-PROD-01.meridianhcs.local
#1710773009
ssh -l lina.nguyen WEB-EXT-01.meridianhcs.local
#1710773461
nano /home/lina.nguyen/projects/data-pipeline/config.yaml
#1710773558
git log --oneline -10
#1710773587
git log --oneline --graph -15
#1710773606
lsmod | head
#1710774237
ssh lina.nguyen@WEB-EXT-01.meridianhcs.local
#1710774376
ssh lina.nguyen@10.10.4.10
#1710774728
nano /home/lina.nguyen/repos/infra-config/Makefile
#1710776267
vim /home/lina.nguyen/projects/data-pipeline/deploy.sh
#1710776312
emacs -nw /opt/company/webapp/requirements.txt
#1710776358
python3 -m pytest tests/ -v --tb=short
#1710776418
python3 -m pytest tests/unit/ -x
#1710776479
python3 -m pytest tests/unit/ -x
#1710776532
git status
#1710776559
git log --oneline -10
#1710776584
npm test
#1710776639
docker logs --tail 50 app
#1710776644
ssh lina.nguyen@DB-PROD-01.meridianhcs.local
#1710776678
du -sh /var/log
#1710778586
ssh -tt lina.nguyen@WEB-EXT-01.meridianhcs.local
#1710778626
ssh -o ConnectTimeout=10 lina.nguyen@DB-PROD-01
#1710778738
ssh lina.nguyen@WEB-EXT-01
#1710779319
ssh -tt lina.nguyen@DB-PROD-01
#1710779745
python3 -m pytest tests/unit/ -x
#1710780458
git stash list
#1710780691
grep -i warning /var/log/syslog | tail
#1710781452
ssh lina.nguyen@10.10.3.10
#1710782238
ssh -p 22 lina.nguyen@APP-INT-01
#1710782738
umask
#1710782794
cd ~
#1710782891
journalctl --no-pager -n 5
#1710783065
getent passwd $(whoami)
#1710783163
ssh -i ~/.ssh/id_rsa lina.nguyen@APP-INT-01
#1710783473
ssh -A lina.nguyen@WEB-EXT-01.meridianhcs.local
