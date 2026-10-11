import re

with open('formatted1.js', 'r') as f:
    content = f.read()

for op in [128, 129, 130, 131, 132, 134, 135, 142, 150, 154, 155, 156, 159, 165]:
    matches = re.finditer(rf'case\s+{op}:', content)
    for m in matches:
        start = max(0, m.start() - 50)
        end = min(len(content), m.start() + 200)
        # find the function it calls
        func_match = re.search(r'await\s+([a-zA-Z0-9_$]+)\(', content[m.start():end])
        if func_match:
            func_name = func_match.group(1)
            # find the function definition
            def_idx = content.find(f'{func_name} = DJ(')
            if def_idx != -1:
                print(f"--- OPCODE {op} -> {func_name} ---")
                print(content[def_idx:def_idx+300])

