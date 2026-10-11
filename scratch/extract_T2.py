import re

with open('formatted0.js', 'r') as f:
    content = f.read()

idx = content.find('onHangup: () => T(R(t))')
start = max(0, idx - 10000)
end = min(len(content), idx + 2000)
# search backwards for T definition
t_def = content.rfind('T =', 0, idx)
t_def2 = content.rfind('function T', 0, idx)
print(f"T = at {t_def}, function T at {t_def2}")
if t_def != -1:
    print(content[max(0, t_def-100):min(len(content), t_def+500)])
