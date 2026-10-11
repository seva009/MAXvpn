import re

with open('formatted1.js', 'r') as f:
    content = f.read()

# search for uses of Cli or ra
matches = re.finditer(r'\b(Cli|ra)\(', content)
for m in matches:
    print(content[max(0, m.start() - 100):min(len(content), m.start() + 400)])
    print("-------")
