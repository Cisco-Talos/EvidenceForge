#1710769814
python3 -c 'import pandas as pd; print(pd.__version__)'
#1710769867
find . -name '*.csv' -o -name '*.xlsx' | head
#1710770058
head -5 data.csv 2>/dev/null
#1710773514
psql -c '\dt'
#1710774569
hostname -f
#1710774752
ls -ltr
#1710774996
history | tail -15
#1710778364
jupyter --paths 2>/dev/null | head
#1710778644
date -u
#1710778881
command -v python3
#1710783602
psql -c 'SELECT now(), current_database(), current_user'
#1710783656
python3 -m pip show sqlalchemy
