import re

with open('formatted1.js', 'r') as f:
    content = f.read()

idx = content.find('t(84,')
if idx != -1:
    print(content[max(0, idx - 100):min(len(content), idx + 200)])

# Find where Cli (84) or ra is used in formatted1.js
