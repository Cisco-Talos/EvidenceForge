#1710773694
grep -R "select .* from" . 2>/dev/null | head
#1710773881
resolvectl status 2>/dev/null | head -30
#1710773984
free -h
#1710777264
python3 -c 'import pandas as pd; print(pd.__version__)'
#1710777375
find . -name '*.csv' -o -name '*.xlsx' | head
#1710777890
groups
