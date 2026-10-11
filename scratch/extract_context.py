with open('formatted1.js', 'r') as f:
    content = f.read()

idx = content.find('case 137:')
if idx != -1:
    print(content[idx-1000:idx+2000])

