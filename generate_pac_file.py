# Define your proxy rules here
rules = [
    "if (shExpMatch(url, 'https:*')) return 'PROXY https-proxy.example.com:8080';",
    "if (shExpMatch(url, 'http:*')) return 'PROXY http-proxy.example.com:8080';",
    "return 'DIRECT';"
]

# Write the PAC file
with open('proxy.pac', 'w') as f:
    f.write('function FindProxyForURL(url, host) {\n')
    for rule in rules:
        f.write('  ' + rule + '\n')
    f.write('}')
