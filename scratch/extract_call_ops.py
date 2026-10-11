import re

with open('formatted1.js', 'r') as f:
    content = f.read()

for op in [78, 128, 129, 130, 131, 132, 134, 135, 136, 137, 142, 150, 154, 155, 156, 158, 159, 165]:
    matches = re.finditer(rf'\(\s*{op}\s*,', content)
    for m in matches:
        start = max(0, m.start() - 100)
        end = min(len(content), m.start() + 200)
        print(f"--- OPCODE {op} MATCH ---")
        print(content[start:end])

