import re

with open('formatted1.js', 'r') as f:
    content = f.read()

for op in [77, 79, 80, 81, 82, 83, 136, 138, 142]:
    matches = re.finditer(rf'\(\s*{op}\s*,', content)
    for m in matches:
        print(f"--- OPCODE {op} ---")
        start = max(0, m.start() - 150)
        end = min(len(content), m.start() + 200)
        print(content[start:end])

