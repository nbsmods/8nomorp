#!/usr/bin/env python3
import struct
import unittest

from verify_native import branch_target, compare_reference, discover, verify


def fixture():
    original = bytearray(0x600)
    original[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<H', original, 18, 183)
    struct.pack_into('<Q', original, 24, 0x200)
    struct.pack_into('<Q', original, 32, 64)
    struct.pack_into('<HH', original, 54, 56, 3)
    struct.pack_into('<IIQQQQQQ', original, 64, 1, 5, 0, 0, 0, 0x400, 0x400, 0x1000)
    struct.pack_into('<IIQQQQQQ', original, 120, 1, 6, 0x400, 0x1400, 0, 0x200, 0x200, 0x1000)
    struct.pack_into('<IIQQQQQQ', original, 176, 2, 6, 0x400, 0x1400, 0, 32, 32, 8)
    struct.pack_into('<QQ', original, 0x400, 12, 0x200)
    ref = bytearray(original)
    struct.pack_into('<I', ref, 0x240, 0x94000000 | ((0x300 - 0x240) // 4))
    ref[0x280:0x284] = b'\xc0\x03\x5f\xd6'
    out = bytearray(ref)
    struct.pack_into('<Q', out, 24, 0)
    struct.pack_into('<I', out, 0x200, 0xd65f03c0)
    struct.pack_into('<I', out, 0x240, 0x94000000 | ((0x280 - 0x240) // 4))
    return original, ref, out


class VerifyTests(unittest.TestCase):
    def test_discovery(self):
        source, ref, out = fixture()
        for image in (ref, out):
            struct.pack_into('<IIII', image, 0x300,
                             0xa9bb7bfd, 0x910003fd, 0xa90107e0, 0xa9020fe2)
            struct.pack_into('<I', image, 0x33c, 0xd61f03a0)
        self.assertEqual(discover(ref), (0x300, 0x33c, 1))
        verify(source, out)
        self.assertEqual(compare_reference(ref, out)[0], 1)
        struct.pack_into('<I', ref, 0x340, 0xd61f03a0)
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            discover(ref)

    def test_discovery_requires_callers(self):
        _, ref, _ = fixture()
        struct.pack_into('<IIII', ref, 0x300,
                         0xa9bb7bfd, 0x910003fd, 0xa90107e0, 0xa9020fe2)
        struct.pack_into('<I', ref, 0x33c, 0xd61f03a0)
        struct.pack_into('<I', ref, 0x240, 0)
        with self.assertRaisesRegex(ValueError, 'no direct callers'):
            discover(ref)

    def test_valid(self):
        source, ref, out = fixture()
        verify(source, out, resolver=0x300)
        self.assertEqual(compare_reference(ref, out, resolver=0x300, expected=1)[0], 1)

    def test_unpatched_call(self):
        source, ref, out = fixture()
        out[0x240:0x244] = ref[0x240:0x244]
        with self.assertRaisesRegex(ValueError, 'unpatched'):
            verify(source, out, resolver=0x300)

    def test_runtime_data_leak(self):
        source, _, out = fixture()
        out[0x500] = 1
        with self.assertRaisesRegex(ValueError, 'non-executable'):
            verify(source, out, resolver=0x300)

    def test_unexpected_code_change(self):
        _, ref, out = fixture()
        out[0x290] ^= 1
        with self.assertRaisesRegex(ValueError, 'unexpected executable'):
            compare_reference(ref, out, resolver=0x300, expected=1)

    def test_external_target(self):
        _, ref, out = fixture()
        struct.pack_into('<I', out, 0x240, 0x94000000 | ((0x1400 - 0x240) // 4))
        with self.assertRaisesRegex(ValueError, 'invalid direct call'):
            compare_reference(ref, out, resolver=0x300, expected=1)

    def test_truncated(self):
        source, _, out = fixture()
        with self.assertRaises(ValueError):
            verify(source, out[:80])

    def test_signed_branch(self):
        self.assertEqual(branch_target(0x1000, 0x97ffffff), 0xffc)


if __name__ == '__main__':
    unittest.main()
