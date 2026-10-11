import re

with open('formatted1.js', 'r') as f:
    content = f.read()

idx = content.find('HUNGUP')
if idx != -1:
    print(content[max(0, idx - 100):min(len(content), idx + 200)])
else:
    print("Not found HUNGUP")

