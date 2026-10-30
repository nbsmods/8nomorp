"""Recover scrambled Promon string IDs using the original native resolver.

Values must also occur in the authenticated LBTS table emitted by `all`.
Dense, already-supported index layouts are left unchanged.
"""
import json
from pathlib import Path
import re

METHOD = re.compile(r'^\.method .*\bstatic\b.*\bnative\b\s+(\w+)\(I\)Ljava/lang/String;', re.M)
CONST = re.compile(r'^\s*const(?:/[\w]+)?\s+([vp]\d+),\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*(?:#.*)?$')


def recover(binary, shield, base, decoded, patched, work, run):
    resolvers = []
    for path in decoded.rglob('*.smali'):
        source = path.read_text()
        match = METHOD.search(source)
        if match:
            resolvers.append((path, source, match.group(1)))
    if len(resolvers) != 1:
        raise ValueError('expected exactly one native string resolver')
    path, source, method = resolvers[0]
    owner = re.search(r'^\.class .* (L[^;]+);', source, re.M).group(1)[1:]
    namespace = owner.rsplit('/', 1)[0] + '/'
    target = patched / path.relative_to(decoded)
    rebuilt = target.read_text()
    body = re.search(r'(^\.method [^\n]*\b' + re.escape(method) + r'\(I\)Ljava/lang/String;\n)(.*?)(^\.end method)', rebuilt, re.M | re.S)
    if not body:
        raise ValueError('patched resolver method not found')
    authenticated = [json.loads(m.group(1)) for m in re.finditer(
        r'const-string/jumbo\s+v0,\s*("(?:[^"\\]|\\.)*")', body.group(2))]
    if not authenticated:
        raise ValueError('authenticated LBTS string table missing')
    ids = set()
    for candidate in decoded.rglob('*.smali'):
        constants = {}
        for line in candidate.read_text().splitlines():
            if line.lstrip().startswith(('.method ', ':')):
                constants.clear()
            literal = CONST.match(line)
            if literal:
                constants[literal.group(1)] = int(literal.group(2), 0) & 0xffffffff
                continue
            call = re.search(r'invoke-static(?:/range)?\s+\{([vp]\d+)(?:\s*\.\.\s*\1)?\},\s+L([^;]+);->\w+\(I\)Ljava/lang/String;', line)
            if call and call.group(2).startswith(namespace) and call.group(1) in constants:
                ids.add(constants[call.group(1)])
            # Do not propagate a literal past an instruction writing its register.
            written = re.match(r'\s*(?!invoke-|if-|return|sput|iput|aput|monitor-)\w[\w/-]*\s+([vp]\d+)(?:,|\s*$)', line)
            if written:
                constants.pop(written.group(1), None)
    if not ids or all(value < len(authenticated) for value in ids):
        return False
    clinit = re.search(r'^\.method .*<clinit>\(\)V\n(.*?)^\.end method', source, re.M | re.S)
    if not clinit:
        raise ValueError('sparse resolver has no registration initializer')
    constants, registrations = {}, []
    for line in clinit.group(1).splitlines():
        literal = CONST.match(line)
        if literal:
            constants[literal.group(1)] = int(literal.group(2), 0) & 0xffffffff
        call = re.search(r'invoke-static\s+\{[vp]\d+,\s*([vp]\d+)\},.*\(Ljava/lang/Class;I\)V', line)
        if call and call.group(1) in constants:
            registrations.append(constants[call.group(1)])
    if len(registrations) != 1:
        raise ValueError('ambiguous sparse resolver registration ID')
    inputs, output = work / 'string-ids.txt', work / 'resolved-strings.txt'
    inputs.write_text(''.join(f'{value:08x}\n' for value in sorted(ids)))
    run([str(binary), 'strings', str(shield), str(base), owner,
         str(registrations[0]), str(inputs), str(output)])
    values = {}
    for line in output.read_text().splitlines():
        key, encoded = line.split('\t')
        key, value = int(key, 16), bytes.fromhex(encoded).decode('utf-8')
        if key not in ids or key in values or value not in authenticated:
            raise ValueError('native string is duplicate, unexpected, or not authenticated by LBTS')
        values[key] = value
    if set(values) != ids:
        raise ValueError('incomplete sparse string recovery')
    signed = lambda value: value if value < 0x80000000 else value - 0x100000000
    ordered = sorted(values, key=signed)
    lines = ['    .locals 1', '    sparse-switch p0, :promon_sparse',
             '    const/4 v0, 0x0', '    return-object v0']
    for i, key in enumerate(ordered):
        lines.extend([f'    :promon_value_{i}',
                      '    const-string/jumbo v0, ' + json.dumps(values[key], ensure_ascii=True),
                      '    return-object v0'])
    lines.extend(['    :promon_sparse', '    .sparse-switch'])
    for i, key in enumerate(ordered):
        lines.append(f'        {signed(key):#x} -> :promon_value_{i}')
    lines.extend(['    .end sparse-switch', ''])
    target.write_text(rebuilt[:body.start(2)] + '\n'.join(lines) + rebuilt[body.end(2):])
    print(f'Recovered {len(values)} sparse string IDs; every value verified against authenticated LBTS plaintext.', flush=True)
    return True
