import re

with open('formatted0.js', 'r') as f:
    content = f.read()

idx = content.find('function T(e)')
if idx != -1:
    print(content[idx:idx+1500])

