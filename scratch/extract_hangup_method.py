import re

with open('formatted1.js', 'r') as f:
    content = f.read()

idx = content.find('hangup({')
if idx != -1:
    print(content[max(0, idx - 400):min(len(content), idx + 800)])
else:
    # search for hangup(
    matches = re.finditer(r'hangup\s*\(', content)
    for m in matches:
        print(content[max(0, m.start() - 200):min(len(content), m.start() + 400)])
        print("-------")

