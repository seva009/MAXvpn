import re

with open('formatted1.js', 'r') as f:
    content = f.read()

# find hangup: or hangup( in formatted1.js exported sdk or similar
idx = content.find('hangup(e)')
if idx != -1:
    print("Found hangup(e)")
else:
    matches = re.finditer(r'hangup\s*=?\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z0-9_]+)\s*=>\s*\{', content)
    for m in matches:
        print(content[max(0, m.start() - 100):min(len(content), m.start() + 400)])
        print("-------")
        
