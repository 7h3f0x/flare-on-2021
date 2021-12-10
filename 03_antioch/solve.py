import os
import shutil

if os.path.exists('result'):
    shutil.rmtree('result')

os.mkdir('result')
os.chdir('result')

os.system("tar xvf ../antioch.tar")

res = []
with open('../res.txt', "r") as f:
    for line in f.read().splitlines():
        if not line:
            continue
        l = line.split()
        res.append((l[0], int(l[-1])))

res = sorted(res, key=lambda x: x[1])

for r in res:
    os.system("tar xvf {}/layer.tar".format(r[0]))

os.system('echo "consult" | ../AntiochOS')

