import re

with open('formatted1.js', 'r') as f:
    content = f.read()

idx = content.find('hangup:')
while idx != -1:
    print(content[max(0, idx - 150):min(len(content), idx + 250)])
    print("-------")
    idx = content.find('hangup:', idx + 1)
    
idx2 = content.find('hangup(')
while idx2 != -1:
    print(content[max(0, idx2 - 150):min(len(content), idx2 + 250)])
    print("-------")
    idx2 = content.find('hangup(', idx2 + 1)
