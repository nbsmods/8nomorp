#!/usr/bin/env python3
"""Independent structural check of an experimental native export (not launch validation)."""
import argparse
import hashlib
import struct


class Elf:
    def __init__(self, data):
        self.data = data
        if data[:6] != b'\x7fELF\x02\x01' or self.read('<H', 18)[0] != 183:
            raise ValueError('expected little-endian ARM64 ELF')
        phoff = self.read('<Q', 32)[0]
        size, count = self.read('<HH', 54)
        if size != 56:
            raise ValueError('invalid program header size')
        self.headers = [self.read('<IIQQQQQQ', phoff + i * size) for i in range(count)]
        self.loads = [p for p in self.headers if p[0] == 1]
        for _, _, offset, _, _, filesz, memsz, _ in self.loads:
            if filesz > memsz or offset + filesz > len(data):
                raise ValueError('invalid load segment bounds')
        self.tags = {}
        for p in self.headers:
            if p[0] == 2:
                for offset in range(p[2], p[2] + p[5], 16):
                    tag, value = self.read('<QQ', offset)
                    if not tag:
                        break
                    self.tags[tag] = value

    def read(self, fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(self.data):
            raise ValueError('truncated ELF')
        return struct.unpack_from(fmt, self.data, offset)

    def offset(self, va, size=1):
        for _, _, offset, start, _, filesz, _, _ in self.loads:
            if start <= va and va - start + size <= filesz:
                return offset + va - start
        raise ValueError(f'address is not file-backed: {va:#x}')

    def executable(self, va):
        return any(flags & 1 and start <= va < start + filesz
                   for _, flags, _, start, _, filesz, _, _ in self.loads)

    def relocations(self):
        for address, size in ((self.tags.get(7, 0), self.tags.get(8, 0)),
                              (self.tags.get(23, 0), self.tags.get(2, 0))):
            if size % 24:
                raise ValueError('invalid relocation table size')
            if size:
                offset = self.offset(address, size)
                for i in range(0, size, 24):
                    yield self.read('<QQq', offset + i)


def branch_target(pc, word):
    delta = word & 0x3ffffff
    if delta & (1 << 25):
        delta -= 1 << 26
    return pc + delta * 4


def discover(reference, require_calls=True):
    """Independent structural discovery, with no version or hash allowlist."""
    ref = Elf(reference)
    entries, tails = [], []
    prefix = struct.pack('<IIII', 0xa9bb7bfd, 0x910003fd, 0xa90107e0, 0xa9020fe2)
    for _, flags, offset, start, _, size, _, _ in ref.loads:
        if not flags & 1:
            continue
        for local in range(0, size - 3, 4):
            position = offset + local
            if reference[position:position + 4] == b'\xa0\x03\x1f\xd6':
                tails.append(start + local)
            if local + 16 <= size and reference[position:position + 16] == prefix:
                entries.append(start + local)
    if len(entries) != 1 or len(tails) != 1:
        raise ValueError('ambiguous or unsupported resolver structure')
    resolver = entries[0]
    calls = sum(
        ref.read('<I', offset + local)[0] & 0xfc000000 == 0x94000000 and
        branch_target(start + local, ref.read('<I', offset + local)[0]) == resolver
        for _, flags, offset, start, _, size, _, _ in ref.loads if flags & 1
        for local in range(0, size - 3, 4))
    if require_calls and not calls:
        raise ValueError('resolver has no direct callers')
    return resolver, tails[0], calls


def verify(original, unpacked, resolver=None):
    if resolver is None:
        resolver, _, _ = discover(unpacked, require_calls=False)
    before, after = Elf(original), Elf(unpacked)
    if len(original) != len(unpacked) or before.headers != after.headers:
        raise ValueError('file length/program headers changed')
    if before.tags != after.tags:
        raise ValueError('dynamic metadata changed')
    allowed = bytearray(len(original))
    allowed[24:32] = b'\x01' * 8
    if after.read('<Q', 24)[0] != 0:
        raise ValueError('packed ELF entry point was not cleared')
    executable_bytes = 0
    for _, flags, offset, _, _, filesz, _, _ in before.loads:
        if flags & 1:
            allowed[offset:offset + filesz] = b'\x01' * filesz
            executable_bytes += sum(a != b for a, b in zip(
                original[offset:offset + filesz], unpacked[offset:offset + filesz]))
    if any(a != b and not ok for a, b, ok in zip(original, unpacked, allowed)):
        raise ValueError('non-executable bytes changed (possible emulator state leak)')
    for va, info, _ in before.relocations():
        if info & 0xffffffff == 0:
            continue
        try:
            offset = before.offset(va, 8)
        except ValueError:
            continue  # BSS relocations have no serialized bytes
        if original[offset:offset + 8] != unpacked[offset:offset + 8]:
            raise ValueError(f'relocation slot contains runtime state: {va:#x}')
    init = after.offset(before.tags[12], 4)
    if after.read('<I', init)[0] != 0xd65f03c0:
        raise ValueError('packed constructor was not disabled')
    # Insist no BL to the common resolver remains in any executable segment.
    for _, flags, offset, start, _, filesz, _, _ in after.loads:
        if not flags & 1:
            continue
        for local in range(0, filesz - 3, 4):
            pc = start + local
            word = after.read('<I', offset + local)[0]
            if word & 0xfc000000 == 0x94000000 and branch_target(pc, word) == resolver:
                raise ValueError(f'unpatched resolver call: {pc:#x}')
    return before, after, executable_bytes


def compare_reference(reference, exported, resolver=None, expected=None):
    """Check each changed resolver BL against its exported executable target."""
    if resolver is None:
        resolver, _, discovered = discover(reference)
        if expected is None:
            expected = discovered
    if expected is None:
        raise ValueError('explicit resolver requires an expected call count')
    ref, out = Elf(reference), Elf(exported)
    calls, special = 0, {}
    allowed = bytearray(len(exported))
    allowed[24:32] = b'\x01' * 8  # ELF e_entry is cleared by the exporter
    # Every executable byte must match the decrypted image, except verified
    # call-site replacements, restored relocation slots and disabled DT_INIT.
    init = out.offset(out.tags[12], 4)
    allowed[init:init + 4] = b'\x01' * 4
    for va, info, _ in out.relocations():
        if info & 0xffffffff:
            try:
                offset = out.offset(va, 8)
            except ValueError:
                continue
            allowed[offset:offset + 8] = b'\x01' * 8
    for _, flags, offset, start, _, filesz, _, _ in ref.loads:
        if not flags & 1:
            continue
        for local in range(0, filesz - 3, 4):
            pc = start + local
            word = ref.read('<I', offset + local)[0]
            if word & 0xfc000000 != 0x94000000 or branch_target(pc, word) != resolver:
                continue
            patched = out.read('<I', out.offset(pc, 4))[0]
            target = branch_target(pc, patched)
            if patched & 0xfc000000 != 0x94000000 or target == resolver or not out.executable(target):
                raise ValueError(f'invalid direct call: {pc:#x} -> {target:#x}')
            calls += 1
            offset_out = out.offset(pc, 4)
            allowed[offset_out:offset_out + 4] = b'\x01' * 4
            if pc in (0x6675fc, 0x7b0b00):
                special[hex(pc)] = hex(target)
    if calls != expected:
        raise ValueError(f'expected {expected} calls, checked {calls}')
    for _, flags, offset, start, _, filesz, _, _ in out.loads:
        if flags & 1:
            ref_offset = ref.offset(start, filesz)
            for i in range(filesz):
                if not allowed[offset + i] and reference[ref_offset + i] != exported[offset + i]:
                    raise ValueError(f'unexpected executable change: {start + i:#x}')
    return calls, special


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original')
    parser.add_argument('exported')
    parser.add_argument('--decrypted-reference', required=True,
                        help='unpatched, fully decrypted analysis dump from the matching input')
    args = parser.parse_args()
    try:
        with open(args.original, 'rb') as f:
            original = f.read()
        with open(args.exported, 'rb') as f:
            exported = f.read()
        with open(args.decrypted_reference, 'rb') as f:
            reference = f.read()
        resolver, _, expected = discover(reference)
        _, _, changed = verify(original, exported, resolver)
        count, special = compare_reference(reference, exported, resolver, expected)
    except (OSError, ValueError, KeyError, struct.error) as exc:
        parser.exit(1, f'FAIL: {exc}\n')
    print(f'PASS: ELF layout, metadata, writable bytes, relocation slots; {count} direct calls')
    print(f'Changed executable bytes: {changed}; formerly rejected calls: {special}')
    print(f'SHA-256: {hashlib.sha256(exported).hexdigest()}')
    print('Android launch, behavior and server compatibility: NOT TESTED')


if __name__ == '__main__':
    main()
