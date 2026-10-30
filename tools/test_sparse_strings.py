#!/usr/bin/env python3
from pathlib import Path
import tempfile
import unittest

from sparse_strings import recover


class SparseTests(unittest.TestCase):
    def fixture(self, root, token=0x12345678):
        decoded, patched = root/'decoded', root/'patched'
        decoded.mkdir(); patched.mkdir()
        original = ('.class public Lshield/Resolver;\n.super Ljava/lang/Object;\n'
                    '.method static constructor <clinit>()V\n.locals 2\n'
                    'const-class v0, Lshield/Resolver;\nconst v1, 7\n'
                    'invoke-static {v0, v1}, Lshield/Registrar;->a(Ljava/lang/Class;I)V\nreturn-void\n.end method\n'
                    '.method public static native value(I)Ljava/lang/String;\n.end method\n')
        (decoded/'Resolver.smali').write_text(original)
        (patched/'Resolver.smali').write_text(
            '.class public Lshield/Resolver;\n.super Ljava/lang/Object;\n'
            '.method public static value(I)Ljava/lang/String;\n.locals 1\n'
            'const-string/jumbo v0, "connectivity"\nreturn-object v0\n.end method\n')
        (decoded/'Caller.smali').write_text(
            f'.method public test()V\nconst v0, {token:#x}\n'
            'invoke-static {v0}, Lshield/Wrapper;->a(I)Ljava/lang/String;\n.end method\n')
        return decoded, patched

    def test_sparse_ids_authenticated_and_signed_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); decoded,patched=self.fixture(root,0xf2345678)
            def run(command):
                self.assertEqual(command[4:6], ['shield/Resolver','7'])
                Path(command[-1]).write_text('f2345678\t'+b'connectivity'.hex()+'\n')
            self.assertTrue(recover(Path('tool'),Path('shield'),Path('base'),decoded,patched,root,run))
            source=(patched/'Resolver.smali').read_text()
            self.assertIn('sparse-switch p0',source)
            self.assertIn('-0xdcba988 -> :promon_value_0',source)
            self.assertIn('"connectivity"',source)

    def test_unauthenticated_native_string_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);decoded,patched=self.fixture(root)
            before=(patched/'Resolver.smali').read_bytes()
            def run(command):
                Path(command[-1]).write_text('12345678\t'+b'guessed'.hex()+'\n')
            with self.assertRaisesRegex(ValueError,'not authenticated'):
                recover(Path('tool'),Path('shield'),Path('base'),decoded,patched,root,run)
            self.assertEqual((patched/'Resolver.smali').read_bytes(),before)

    def test_dense_layout_does_not_run_native_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);decoded,patched=self.fixture(root,0)
            def run(command): raise AssertionError('dense layout must stay unchanged')
            self.assertFalse(recover(Path('tool'),Path('shield'),Path('base'),decoded,patched,root,run))

    def test_range_invoke_high_register(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);decoded,patched=self.fixture(root)
            (decoded/'Caller.smali').write_text(
                '.method public test()V\nconst v25, 0x12345678\n'
                'invoke-static/range {v25 .. v25}, Lshield/Wrapper;->a(I)Ljava/lang/String;\n.end method\n')
            def run(command):
                self.assertEqual(Path(command[-2]).read_text(),'12345678\n')
                Path(command[-1]).write_text('12345678\t'+b'connectivity'.hex()+'\n')
            self.assertTrue(recover(Path('tool'),Path('shield'),Path('base'),decoded,patched,root,run))

    def test_float_annotation_does_not_hide_integer_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);decoded,patched=self.fixture(root)
            (decoded/'Caller.smali').write_text(
                '.method public test()V\nconst v0, 0x4bca030f    # 2.647811E7f\n'
                'invoke-static {v0}, Lshield/Wrapper;->a(I)Ljava/lang/String;\n.end method\n')
            def run(command):
                self.assertEqual(Path(command[-2]).read_text(),'4bca030f\n')
                Path(command[-1]).write_text('4bca030f\t'+b'connectivity'.hex()+'\n')
            self.assertTrue(recover(Path('tool'),Path('shield'),Path('base'),decoded,patched,root,run))


if __name__=='__main__': unittest.main()
