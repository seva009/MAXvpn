import re

with open('formatted1.js', 'r') as f:
    content = f.read()

for alias in ['sa', 'aa', 'ia', 'ra', 'ua', 'la']:
    # We must only match word boundaries like sa({ ... }) or sa(some_var)
    matches = re.finditer(rf'\b{alias}\(', content)
    for m in matches:
        start = max(0, m.start() - 250)
        end = min(len(content), m.start() + 250)
        # to avoid printing too much, print the match context
        print(f"--- ALIAS {alias} ---")
        print(content[start:end])

