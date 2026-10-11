import re

with open('formatted0.js', 'r') as f:
    content = f.read()

matches = re.finditer(r'onHangup(?:\s*:\s*|\s*\(\s*\)\s*=>|\s*\(\s*\)\s*\{)', content)
for m in matches:
    start = max(0, m.start() - 150)
    end = min(len(content), m.start() + 450)
    print("--- onHangup ---")
    print(content[start:end])

