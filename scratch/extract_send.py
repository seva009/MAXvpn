import re

with open('formatted1.js', 'r') as f:
    content = f.read()

matches = re.finditer(r'send\(\s*(\d{2,3})', content)
for m in matches:
    print(f"Match: {m.group(0)} at {m.start()}")

