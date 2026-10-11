import re

with open('formatted1.js', 'r') as f:
    content = f.read()

for func in ['bli', 'xli', 'Sli', 'Cli', 'wli', 'Tli', 'yli']:
    matches = re.finditer(rf'{func}\(', content)
    for m in matches:
        print(f"--- {func} usage ---")
        start = max(0, m.start() - 100)
        end = min(len(content), m.start() + 200)
        print(content[start:end])

