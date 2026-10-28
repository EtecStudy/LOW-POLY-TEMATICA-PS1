"""Parser do container ``\\x7FCNT`` usado em pacotes de PS4 (e PS5).

Fonte: PSDevWiki "PKG files (PS4)" e LibOrbisPkg/LibProsperoPKG.

Aqui só existe **leitura**. Escrever um .pkg de PS4 instalável exige montar a
imagem PFS (XTS-AES-128 + árvore de Merkle + assinatura), o que depende das
chaves EKPFS/debug da Sony. Ver ``docs/O-QUE-DA-E-O-QUE-NAO-DA.md``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .crypto import sha256
from .sfo import SFO, read_sfo

MAGIC = 0x7F434E54                 # b"\x7FCNT"
HEADER_SIZE = 0x1000
ENTRY_SIZE = 0x20
FOOTER_SIZE = 0x20

FLAG_ENCRYPTED = 0x80000000        # bit em flags1 que marca entrada cifrada

ENTRY_NAMES = {
    0x0001: "digests",
    0x0010: "entry_keys",
    0x0020: "image_key",
    0x0080: "general_digests",
    0x0100: "meta_entries",
    0x0200: "entry_names",
    0x0400: "license.dat",
    0x0401: "license.info",
    0x0402: "nptitle.dat",
    0x0403: "npbind.dat",
    0x0404: "selfinfo.dat",
    0x0406: "imageinfo.dat",
    0x0409: "psreserved.dat",
    0x1000: "param.sfo",
    0x1001: "playgo-chunk.dat",
    0x1002: "playgo-chunk.sha",
    0x1003: "playgo-manifest.xml",
    0x1004: "pronunciation.xml",
    0x1005: "pronunciation.sig",
    0x1006: "pic0.png",
    0x1007: "pic1.png",
    0x1008: "icon0.png",
    0x1009: "icon1.png",
    0x1220: "shareoverlay",
    0x1240: "shareparam",
    0x1400: "mbsbackup.dat",
    0xC001: "mbsbackup.dat?",
}

PS4_CONTENT_TYPES = {
    0x04: "PS4GD (jogo completo)",
    0x05: "PS4 patch/update",
    0x06: "PS4 remaster?",
    0x07: "PS4 additional content (DLC)",
    0x08: "PS4 additional license",
    0x0C: "PS4 theme",
    0x0F: "PS4 media?",
    0x10: "PS5 game?",
    0x11: "PS5 patch?",
    0x12: "PS5 additional content?",
    0x15: "PS4/PS5 non-game?",
    0x16: "PS4/PS5 media app?",
    0x17: "PS4/PS5 bundled?",
    0x19: "PS5 additional license?",
    0x1A: "PS5 theme?",
    0x1B: "PS5 free-to-play?",
    0x1C: "PS5 remaster?",
    0x1D: "PS5 shared content?",
    0x1E: "PS5 editorial?",
    0x1F: "PS5 database?",
}

PS4_DRM_TYPES = {
    0x01: "PS4 (local)",
    0x02: "PS4 (network?)",
    0x03: "PS4 local + network",
    0x04: "PS5?",
    0x07: "PS5 local + network?",
    0x0A: "PS4/PS5 unknown",
    0x0B: "PS4/PS5 unknown",
    0x0C: "PS4/PS5 unknown",
    0x0F: "PS4/PS5 unknown",
    0x10: "PS4/PS5 unknown",
    0x11: "PS4/PS5 unknown",
    0x13: "PS4/PS5 unknown",
}


class Pkg4Error(Exception):
    pass


@dataclass
class Entry4:
    id: int
    filename_offset: int
    flags1: int
    flags2: int
    offset: int
    size: int
    name: str = ""

    @property
    def encrypted(self) -> bool:
        return bool(self.flags1 & FLAG_ENCRYPTED)

    @property
    def key_index(self) -> int:
        return self.flags2 & 0xFFFF

    @property
    def known_name(self) -> str:
        return ENTRY_NAMES.get(self.id, f"entry_0x{self.id:04X}")

    @staticmethod
    def unpack(buf: bytes) -> "Entry4":
        eid, name_off, flags1, flags2, offset, size = struct.unpack(">IIIIII", buf[:0x18])
        return Entry4(eid, name_off, flags1, flags2, offset, size)

    def pack(self) -> bytes:
        return struct.pack(">IIIIII8x", self.id, self.filename_offset,
                           self.flags1, self.flags2, self.offset, self.size)


@dataclass
class Pkg4:
    magic: int = MAGIC
    pkg_flags: int = 0
    field_0x008: int = 0
    file_count: int = 0
    entry_count: int = 0
    sc_entry_count: int = 0
    entry_count_2: int = 0
    table_offset: int = 0
    entry_data_size: int = 0
    body_offset: int = 0
    body_size: int = 0
    content_offset: int = 0
    content_size: int = 0
    content_id: str = ""
    drm_type: int = 0
    content_type: int = 0
    content_flags: int = 0
    promote_size: int = 0
    version_date: int = 0
    version_hash: int = 0
    iro_tag: int = 0
    drm_type_version: int = 0
    pfs_image_count: int = 0
    pfs_image_flags: int = 0
    pfs_image_offset: int = 0
    pfs_image_size: int = 0
    mount_image_offset: int = 0
    mount_image_size: int = 0
    pkg_size: int = 0
    pfs_signed_size: int = 0
    pfs_cache_size: int = 0
    digest_entries1: bytes = b""
    digest_entries2: bytes = b""
    digest_table_digest: bytes = b""
    digest_body_digest: bytes = b""
    pfs_image_digest: bytes = b""
    pfs_signed_digest: bytes = b""
    pkg_digest: bytes = b""
    entries: list[Entry4] = field(default_factory=list)
    raw: bytes = b""

    @staticmethod
    def parse(blob: bytes) -> "Pkg4":
        if len(blob) < HEADER_SIZE:
            raise Pkg4Error("arquivo menor que 0x1000 (header PS4)")
        magic = struct.unpack_from(">I", blob, 0)[0]
        if magic != MAGIC:
            raise Pkg4Error(
                f"magic 0x{magic:08X} não é \\x7FCNT (0x{MAGIC:08X}). "
                "Se for PS3/PSP/Vita (\\x7FPKG) use o parser ps3."
            )
        p = Pkg4(raw=blob, magic=magic)
        (p.pkg_flags, p.field_0x008, p.file_count, p.entry_count,
         p.sc_entry_count, p.entry_count_2, p.table_offset,
         p.entry_data_size) = struct.unpack_from(">IIIIHHII", blob, 0x04)
        (p.body_offset, p.body_size, p.content_offset,
         p.content_size) = struct.unpack_from(">QQQQ", blob, 0x20)
        p.content_id = blob[0x40:0x40 + 0x24].split(b"\x00")[0].decode("ascii", "replace")
        (p.drm_type, p.content_type, p.content_flags, p.promote_size,
         p.version_date, p.version_hash) = struct.unpack_from(">IIIIII", blob, 0x70)
        p.iro_tag = struct.unpack_from(">I", blob, 0x98)[0]
        p.drm_type_version = struct.unpack_from(">I", blob, 0x9C)[0]
        p.digest_entries1 = blob[0x100:0x120]
        p.digest_entries2 = blob[0x120:0x140]
        p.digest_table_digest = blob[0x140:0x160]
        p.digest_body_digest = blob[0x160:0x180]
        p.pfs_image_count = struct.unpack_from(">I", blob, 0x404)[0]
        (p.pfs_image_flags, p.pfs_image_offset, p.pfs_image_size,
         p.mount_image_offset, p.mount_image_size, p.pkg_size) = struct.unpack_from(">QQQQQQ", blob, 0x408)
        p.pfs_signed_size, p.pfs_cache_size = struct.unpack_from(">II", blob, 0x438)
        p.pfs_image_digest = blob[0x440:0x460]
        p.pfs_signed_digest = blob[0x460:0x480]
        p.pkg_digest = blob[0xFE0:0x1000]

        # tabela de entradas
        pos = p.table_offset
        for _ in range(p.entry_count):
            if pos + ENTRY_SIZE > len(blob):
                break
            p.entries.append(Entry4.unpack(blob[pos:pos + ENTRY_SIZE]))
            pos += ENTRY_SIZE

        # nomes: entrada 0x200 é a tabela de nomes, em texto claro
        names_blob = p.entry_bytes(0x200)
        if names_blob:
            for e in p.entries:
                if e.filename_offset and e.filename_offset < len(names_blob):
                    e.name = names_blob[e.filename_offset:].split(b"\x00")[0].decode("utf-8", "replace")
        return p

    # ------------------------------------------------------------------ #
    def entry(self, eid: int) -> Optional[Entry4]:
        return next((e for e in self.entries if e.id == eid), None)

    def entry_bytes(self, eid: int) -> Optional[bytes]:
        e = self.entry(eid)
        if not e:
            return None
        return self.raw[e.offset:e.offset + e.size]

    def plaintext_entries(self) -> list[Entry4]:
        """Entradas legíveis sem nenhuma chave (flags1 sem o bit 0x80000000)."""
        return [e for e in self.entries if not e.encrypted]

    def encrypted_entries(self) -> list[Entry4]:
        return [e for e in self.entries if e.encrypted]

    def read_sfo(self) -> Optional[SFO]:
        blob = self.entry_bytes(0x1000)
        if blob and blob[:4] == b"\x00PSF":
            return read_sfo(blob)
        return None

    def verify(self) -> dict:
        out: dict[str, object] = {}
        blob = self.raw
        out["tamanho_real"] = len(blob)
        out["pkg_size_no_header"] = self.pkg_size
        out["coincidem"] = len(blob) == self.pkg_size
        out["entradas"] = len(self.entries)
        out["entradas_texto_claro"] = len(self.plaintext_entries())
        out["entradas_cifradas"] = len(self.encrypted_entries())
        out["pfs_image_presente"] = self.pfs_image_size > 0
        if self.pfs_image_size:
            img = blob[self.pfs_image_offset:self.pfs_image_offset + self.pfs_image_size]
            out["pfs_image_digest_ok"] = sha256(img) == self.pfs_image_digest
        # entry table digest: sha256 de sc_entries + entradas
        if self.table_offset and self.entry_count:
            table = blob[self.table_offset:self.table_offset + self.entry_count * ENTRY_SIZE]
            out["entry_table_sha256"] = sha256(table).hex()
        return out


def detect(blob: bytes) -> str:
    """Diz qual parser serve para os primeiros bytes do arquivo."""
    if len(blob) < 4:
        return "desconhecido"
    magic = struct.unpack_from(">I", blob, 0)[0]
    if magic == 0x7F504B47:
        return "ps3"
    if magic == MAGIC:
        return "ps4"
    if magic == 0x7F464948:          # \x7FFIH - PS5 finalized image
        return "ps5-fih"
    return "desconhecido"
