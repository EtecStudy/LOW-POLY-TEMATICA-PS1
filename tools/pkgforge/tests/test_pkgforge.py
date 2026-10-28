"""Testes do pkgforge. Rode com:  python3 -m unittest discover -s tests -v"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pkgforge.crypto import AES128, aes128_ctr, debug_keystream, pkg_hmac, sha1, xor_stream
from pkgforge.ps3 import (ITEM_DIR, ITEM_FILE, Pkg3, PackOptions, REVISION_DEBUG,
                          build_pkg)
from pkgforge.ps4 import detect
from pkgforge.sfo import SFO, read_sfo

def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLI = [sys.executable, "-m", "pkgforge.cli"]


class TestAES(unittest.TestCase):
    def test_fips197_vector(self):
        key = bytes(range(16))
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = AES128(key).encrypt_block(pt)
        self.assertEqual(ct.hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")

    def test_ctr_roundtrip(self):
        key = bytes(range(16))
        iv = bytes(range(16, 32))
        data = os.urandom(1000)
        self.assertEqual(aes128_ctr(key, iv, aes128_ctr(key, iv, data)), data)


class TestPkgHmac(unittest.TestCase):
    def test_deterministic_and_16_bytes(self):
        h = pkg_hmac(b"abc")
        self.assertEqual(len(h), 16)
        self.assertEqual(h, pkg_hmac(b"abc"))
        self.assertNotEqual(h, pkg_hmac(b"abd"))


class TestDebugKeystream(unittest.TestCase):
    def test_self_inverse(self):
        digest = sha1(b"seed") + b"\x00" * 0x30
        data = bytearray(b"PKGFORGE" * 64)
        ks = debug_keystream(digest, len(data))
        enc = xor_stream(data, ks)
        self.assertNotEqual(enc, bytes(data))
        dec = xor_stream(enc, debug_keystream(digest, len(data)))
        self.assertEqual(dec, bytes(data))

    def test_counter_advances_every_16_bytes(self):
        digest = sha1(b"x") + b"\x00" * 0x30
        ks = list(debug_keystream(digest, 48))
        self.assertEqual(ks[0:16], ks[0:16])
        # blocos diferentes => keystream diferente
        self.assertNotEqual(ks[0:16], ks[16:32])
        self.assertNotEqual(ks[16:32], ks[32:48])


class TestSFO(unittest.TestCase):
    def test_roundtrip(self):
        sfo = SFO()
        sfo.set_str("TITLE", "Low Poly Temática PS1")
        sfo.set_str("TITLE_ID", "NPUB00001")
        sfo.set_str("CATEGORY", "HG")
        sfo.set_int("BOOTABLE", 1)
        blob = sfo.dumps()
        self.assertEqual(blob[:4], b"\x00PSF")
        back = read_sfo(blob)
        self.assertEqual(back.get("TITLE"), "Low Poly Temática PS1")
        self.assertEqual(back.get("BOOTABLE"), 1)
        # chaves em ordem alfabética na tabela
        self.assertEqual(list(back.entries)[:2], sorted(back.entries)[:2])


class TestPackUnpack(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pkgforge-test-")
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(os.path.join(self.src, "USRDIR", "CONTENT"))
        with open(os.path.join(self.src, "USRDIR", "CONTENT", "EBOOT.BIN"), "wb") as fh:
            fh.write(os.urandom(5000))
        with open(os.path.join(self.src, "USRDIR", "ICON0.PNG"), "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n" + os.urandom(300))
        sfo = SFO().set_str("TITLE", "Teste").set_str("TITLE_ID", "NPUB00001") \
                   .set_str("CATEGORY", "HG").set_int("BOOTABLE", 1)
        with open(os.path.join(self.src, "PARAM.SFO"), "wb") as fh:
            fh.write(sfo.dumps())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _pack(self, **kw) -> str:
        opts = PackOptions(content_id="UP0001-NPUB00001_00-TESTEPKG00000001",
                           title_id="NPUB00001", install_directory="NPUB00001", **kw)
        out = os.path.join(self.tmp, "saida.pkg")
        blob = build_pkg(self.src, opts)
        with open(out, "wb") as fh:
            fh.write(blob)
        return out

    def test_layout_do_header(self):
        path = self._pack()
        blob = _read(path)
        pkg = Pkg3.parse(blob)
        self.assertEqual(pkg.revision, REVISION_DEBUG)
        self.assertEqual(pkg.pkg_type, 1)
        self.assertEqual(pkg.content_id, "UP0001-NPUB00001_00-TESTEPKG00000001")
        self.assertEqual(len(blob), pkg.total_size)
        self.assertEqual(pkg.metadata_offset, 0xC0)
        self.assertEqual(pkg.data_offset, pkg.metadata_offset + pkg.metadata_size)
        # cauda: 0x40 de digest + 0x20 de footer
        self.assertEqual(pkg.total_size - (pkg.data_offset + pkg.data_size), 0x60)

    def test_footer_sha1(self):
        blob = _read(self._pack())
        self.assertEqual(blob[-0x20:-0x0C], sha1(blob[:-0x20]))
        self.assertEqual(blob[-0x0C:], b"\x00" * 0x0C)

    def test_roundtrip_conteudo(self):
        path = self._pack()
        blob = _read(path)
        pkg = Pkg3.parse(blob)
        items, plain = pkg.open_all()
        nomes = {i.name for i in items}
        self.assertIn("PARAM.SFO", nomes)
        self.assertIn("USRDIR", nomes)
        self.assertIn("USRDIR/CONTENT/EBOOT.BIN", nomes)

        dirs = [i for i in items if i.item_type == ITEM_DIR]
        files = [i for i in items if i.item_type == ITEM_FILE]
        self.assertTrue(dirs and files)

        original = _read(os.path.join(self.src, "USRDIR", "CONTENT", "EBOOT.BIN"))
        rec = next(i for i in items if i.name == "USRDIR/CONTENT/EBOOT.BIN")
        self.assertEqual(pkg.extract(rec, plain), original)
        self.assertEqual(rec.data_size, len(original))

    def test_sfo_dentro_do_pkg(self):
        blob = _read(self._pack())
        pkg = Pkg3.parse(blob)
        items, plain = pkg.open_all()
        sfo = pkg.find_sfo(items, plain)
        self.assertIsNotNone(sfo)
        self.assertEqual(sfo.get("TITLE_ID"), "NPUB00001")

    def test_area_realmente_ofuscada(self):
        blob = _read(self._pack())
        pkg = Pkg3.parse(blob)
        self.assertNotIn(b"PARAM.SFO", blob[pkg.data_offset:])
        self.assertNotIn(b"EBOOT.BIN", blob[pkg.data_offset:])

    def test_verify(self):
        blob = _read(self._pack())
        rel = Pkg3.parse(blob).verify()
        self.assertTrue(rel["arquivo"]["coincidem"])
        self.assertTrue(rel["arquivo"]["sha1_footer_ok"])
        self.assertEqual(rel["avisos"], [])

    def test_platforma_psp_tem_extended_header(self):
        blob = _read(self._pack(platform="psp", key_selector=0x90))
        pkg = Pkg3.parse(blob)
        self.assertEqual(pkg.pkg_type, 2)
        self.assertIsNotNone(pkg.extended)
        self.assertEqual(blob[0xC0:0xC4], b"\x7Fext")
        self.assertEqual(pkg.metadata_offset, 0x280)
        items, _ = pkg.open_all()
        self.assertTrue(all(i.key_selector == 0x90 for i in items))

    def test_detect(self):
        blob = _read(self._pack())
        self.assertEqual(detect(blob), "ps3")
        self.assertEqual(detect(b"\x7FCNT" + b"\x00" * 0x2000), "ps4")
        self.assertEqual(detect(b"\x7FFIH" + b"\x00" * 100), "ps5-fih")
        self.assertEqual(detect(b"RIFFxxxx"), "desconhecido")


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="pkgforge-cli-")
        self.src = os.path.join(self.tmp, "src")
        os.makedirs(self.src)
        with open(os.path.join(self.src, "DADO.BIN"), "wb") as fh:
            fh.write(os.urandom(1024))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *argv):
        return subprocess.run(CLI + list(argv), cwd=REPO, capture_output=True, text=True)

    def test_fluxo_completo(self):
        pkg = os.path.join(self.tmp, "t.pkg")
        out = os.path.join(self.tmp, "out")

        r = self._run("pack", self.src, pkg, "--content-id",
                      "UP0001-NPUB00002_00-CLITEST000000001", "--quiet")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(pkg))

        r = self._run("info", pkg, "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("UP0001-NPUB00002_00-CLITEST000000001", r.stdout)

        r = self._run("verify", pkg, "--json")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('"sha1_footer_ok": true', r.stdout)

        r = self._run("unpack", pkg, out)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(out, "DADO.BIN")))
        self.assertEqual(_read(os.path.join(out, "DADO.BIN")),
                         _read(os.path.join(self.src, "DADO.BIN")))

    def test_aviso_de_nao_instalavel(self):
        pkg = os.path.join(self.tmp, "t.pkg")
        r = self._run("pack", self.src, pkg, "--content-id",
                      "UP0001-NPUB00003_00-AVISO00000000001")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("NÃO É INSTALÁVEL", r.stderr)

    def test_mk_sfo_e_sfo(self):
        sfo = os.path.join(self.tmp, "PARAM.SFO")
        r = self._run("mk-sfo", sfo, "--title", "Low Poly", "--title-id", "NPUB00004",
                      "--set", "BOOTABLE=1", "--set", "RESOLUTION=48")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self._run("sfo", sfo, "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('"Low Poly"', r.stdout)

    def test_arquivo_inexistente_da_erro_limpo(self):
        """Sem traceback na cara do usuário: mensagem curta e exit code 1."""
        for argv in (["info", "/tmp/nao-existe-pkgforge.pkg"],
                     ["verify", "/tmp/nao-existe-pkgforge.pkg"],
                     ["unpack", "/tmp/nao-existe-pkgforge.pkg", self.tmp]):
            r = self._run(*argv)
            self.assertEqual(r.returncode, 1, argv)
            self.assertIn("não encontrado", r.stderr)
            self.assertNotIn("Traceback", r.stderr)

    def test_content_id_longo_demais_explica_o_formato(self):
        r = self._run("pack", self.src, os.path.join(self.tmp, "x.pkg"),
                      "--content-id", "UP0001-NPUB00006_00-GRANDEDEMAIS000001", "--quiet")
        self.assertEqual(r.returncode, 1)
        self.assertIn("36", r.stderr)
        self.assertIn("UP0001-NPUB30162_00-SCOTTPILGRIM0002", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_origem_vazia_ou_inexistente(self):
        r = self._run("pack", "/tmp/nao-existe-dir-pkgforge", os.path.join(self.tmp, "x.pkg"),
                      "--content-id", "UP0001-NPUB00007_00-TESTEVAZIO00000001", "--quiet")
        self.assertEqual(r.returncode, 1)
        self.assertIn("não existe", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_retail_sem_chave_explica(self):
        """Pacote marcado como retail NÃO abre sem chave -- e precisa explicar por quê."""
        pkg = os.path.join(self.tmp, "r.pkg")
        r = self._run("pack", self.src, pkg, "--content-id",
                      "UP0001-NPUB00005_00-RETAIL0000000001", "--revision", "retail",
                      "--quiet")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(Pkg3.parse(_read(pkg)).revision, 0x8000)

        r = self._run("unpack", pkg, os.path.join(self.tmp, "o2"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("--aes-key-file", r.stderr)
        self.assertIn("FINALIZADO", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
