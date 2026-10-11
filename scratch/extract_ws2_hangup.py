import re

with open('formatted1.js', 'r') as f:
    content = f.read()

# Let's search for {"command":"hangup"
idx = content.find('"hangup"')
while idx != -1:
    print(content[max(0, idx - 100) : min(len(content), idx + 100)])
    print("-------")
    idx = content.find('"hangup"', idx + 1)
