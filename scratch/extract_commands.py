import re

with open('formatted1.js', 'r') as f:
    content = f.read()

idx = content.find('t(78,')
start = max(0, idx - 1000)
end = min(len(content), idx + 2000)
print(content[start:end])

