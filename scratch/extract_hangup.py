import re

with open('formatted1.js', 'r') as f:
    content = f.read()

idx = content.find('QFe =')
if idx != -1:
    print(content[idx:idx+500])

