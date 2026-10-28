"""Modelo de pacotes NPDRM de PS3 / PSP / PS Vita (magic ``\\x7FPKG``).

Fontes do layout (todas públicas):
  * PSDevWiki - "PKG files" (https://www.psdevwiki.com/ps3/PKG_files)
  * pkg2zip (mmozeiko) e PkgUnpack.cpp do PPSSPP, para a semântica dos
    ``flags`` da tabela de itens.

Mapa do arquivo:

    +0x000  header            0xC0 bytes, texto claro
    +0x0C0  extended header   0x40 bytes, texto claro (só PSP/Vita)
    +0x100  hashes/assinaturas
    +0x280  metadata          texto claro (offset/contagem vêm do header)
     ...
    +data_offset              área cifrada: item table, nomes, conteúdo
    -0x40   pkg_digest da cauda
    -0x20   SHA-1 do arquivo inteiro (menos os últimos 0x20 bytes)
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from .crypto import aes128_ctr, debug_keystream, sha1, sha256, xor_stream
from .sfo import SFO, read_sfo

MAGIC = 0x7F504B47                 # b"\x7FPKG"
EXT_MAGIC = 0x7F657874             # b"\x7Fext"
HEADER_SIZE = 0xC0
EXT_HEADER_SIZE = 0x40
FOOTER_SIZE = 0x20
TAIL_DIGEST_SIZE = 0x40
ITEM_RECORD_SIZE = 0x20
ALIGN = 0x10

REVISION_RETAIL = 0x8000
REVISION_DEBUG = 0x0000

TYPE_PS3 = 0x0001
TYPE_PSP_VITA = 0x0002

# Byte 0x1B do item record: tipo de conteúdo.
ITEM_NPDRM_EDAT = 0x02
ITEM_FILE = 0x03
ITEM_DIR = 0x04
ITEM_PSP_EDAT_PGD = 0x05
ITEM_PSP_EDAT_PRX = 0x08
ITEM_PBP = 0x0B

ITEM_TYPE_NAMES = {
    ITEM_NPDRM_EDAT: "NPDRM EDAT",
    ITEM_FILE: "arquivo",
    ITEM_DIR: "diretorio",
    ITEM_PSP_EDAT_PGD: "PSP EDAT (PGD)",
    ITEM_PSP_EDAT_PRX: "PSP EDAT (PRX)",
    ITEM_PBP: "PBP",
}

# IDs de metadata (u32 id, u32 size, u8 value[size]).
META_NAMES = {
    0x01: "DRMType",
    0x02: "ContentType",
    0x03: "PackageType/Flag",
    0x04: "PackageSize",
    0x05: "ToolRevision/PkgVersion",
    0x06: "TitleID",
    0x07: "QADigest",
    0x08: "unk(0x08)",
    0x09: "unk(0x09)",
    0x0A: "InstallDirectory",
    0x0B: "unk(0x0B)",
    0x0C: "unk(0x0C)",
    0x0D: "ItemEntriesInfo",
    0x0E: "SFOInfo",
    0x0F: "UnknownDataInfo",
    0x10: "EntiretyInfo",
    0x11: "PublishingToolsVersion",
    0x12: "SelfInfo",
}

CONTENT_TYPE_NAMES = {
    0x04: "GameData", 0x05: "GameExec", 0x06: "PS1emu", 0x07: "PSP",
    0x09: "Theme", 0x0A: "Widget", 0x0B: "License", 0x0C: "VSHModule",
    0x0D: "PSN Avatar", 0x0E: "PSPgo", 0x0F: "minis", 0x10: "NEOGEO",
    0x11: "VMC", 0x12: "PS2Classic?", 0x13: "ISO2PKG", 0x14: "PSP remaster",
    0x15: "PSP2GD (Vita Game Data)", 0x16: "PSP2AC (Vita AddCont)",
    0x17: "PSP2LA (Vita LiveArea)", 0x18: "PSM", 0x19: "WT",
    0x1A: "PS4GD", 0x1B: "PS4AC", 0x1C: "PS4AL", 0x1D: "PSM for Unity",
    0x1E: "PS4DP", 0x1F: "PSP2Theme", 0x20: "PS5GD",
}


class PkgError(Exception):
    """Erro de formato ou de política (chave ausente, etc.)."""


def _align_up(value: int, align: int = ALIGN) -> int:
    return (value + align - 1) // align * align


@dataclass
class ItemRecord:
    """Um registro de 0x20 bytes da tabela de itens."""

    filename_offset: int
    filename_size: int
    data_offset: int
    data_size: int
    key_selector: int = 0x00        # byte 0x18; 0x90 -> chave PSP
    item_type: int = ITEM_FILE      # byte 0x1B
    name: str = ""

    @property
    def flags(self) -> int:
        """Os 4 bytes em 0x18, como u32 big-endian."""
        return ((self.key_selector & 0xFF) << 24) | (self.item_type & 0xFF)

    @property
    def key_index(self) -> int:
        """``(flags >> 0x1C) & 7`` - índice da chave AES do item."""
        return (self.flags >> 0x1C) & 7

    @property
    def is_dir(self) -> bool:
        return self.item_type == ITEM_DIR

    @staticmethod
    def unpack(buf: bytes) -> "ItemRecord":
        if len(buf) != ITEM_RECORD_SIZE:
            raise PkgError("item record precisa ter 0x20 bytes")
        name_off, name_size, data_off, data_size, flags = struct.unpack(">IIQQI", buf[:0x1C])
        return ItemRecord(
            filename_offset=name_off,
            filename_size=name_size,
            data_offset=data_off,
            data_size=data_size,
            key_selector=(flags >> 24) & 0xFF,
            item_type=flags & 0xFF,
        )

    def pack(self) -> bytes:
        return struct.pack(">IIQQI4x", self.filename_offset, self.filename_size,
                           self.data_offset, self.data_size, self.flags)


@dataclass
class MetaEntry:
    id: int
    data: bytes

    @property
    def name(self) -> str:
        return META_NAMES.get(self.id, f"unk(0x{self.id:X})")

    @property
    def as_int(self) -> Optional[int]:
        if len(self.data) in (4, 8):
            return int.from_bytes(self.data, "big")
        return None

    def pack(self) -> bytes:
        return struct.pack(">II", self.id, len(self.data)) + self.data


@dataclass
class ExtendedHeader:
    """Cabeçalho ``.ext`` de pacotes PSP/Vita (0x40 bytes em 0xC0)."""

    unknown_1: int = 1
    ext_hdr_size: int = EXT_HEADER_SIZE
    ext_data_size: int = 0x180
    main_and_ext_hmac_offset: int = 0x100
    metadata_header_hmac_offset: int = 0x360
    tail_offset: int = 0x1A0
    pkg_key_id: int = 0x00000001      # PSP=0x1, Vita=0xC0000002, PSM=0xC0000004
    full_header_hmac_offset: int = 0
    hmac_main_and_ext: bytes = b"\x00" * 16
    hmac_metadata: bytes = b"\x00" * 16
    hmac_full: bytes = b"\x00" * 16

    def pack(self) -> bytes:
        out = struct.pack(
            ">IIIIIIQIII20x",
            EXT_MAGIC, self.unknown_1, self.ext_hdr_size, self.ext_data_size,
            self.main_and_ext_hmac_offset, self.metadata_header_hmac_offset,
            self.tail_offset, 0, self.pkg_key_id, self.full_header_hmac_offset,
        )
        assert len(out) == EXT_HEADER_SIZE, len(out)
        return out

    @staticmethod
    def unpack(blob: bytes, start: int = 0xC0) -> "ExtendedHeader":
        """``blob`` é o arquivo inteiro: os offsets de HMAC são absolutos."""
        (magic, unk1, hdr_size, data_size, hmac_main_off, hmac_meta_off,
         tail_off, _pad, key_id, hmac_full_off) = struct.unpack_from(">IIIIIIQIII", blob, start)
        if magic != EXT_MAGIC:
            raise PkgError(f"extended header com magic 0x{magic:08X}, esperado 0x{EXT_MAGIC:08X}")
        ext = ExtendedHeader(
            unknown_1=unk1, ext_hdr_size=hdr_size, ext_data_size=data_size,
            main_and_ext_hmac_offset=hmac_main_off,
            metadata_header_hmac_offset=hmac_meta_off, tail_offset=tail_off,
            pkg_key_id=key_id, full_header_hmac_offset=hmac_full_off,
        )
        if hmac_main_off and hmac_main_off + 16 <= len(blob):
            ext.hmac_main_and_ext = blob[hmac_main_off:hmac_main_off + 16]
        if hmac_meta_off and hmac_meta_off + 16 <= len(blob):
            ext.hmac_metadata = blob[hmac_meta_off:hmac_meta_off + 16]
        if hmac_full_off and hmac_full_off + 16 <= len(blob):
            ext.hmac_full = blob[hmac_full_off:hmac_full_off + 16]
        return ext


@dataclass
class Pkg3:
    """Pacote NPDRM completo (PS3/PSP/Vita)."""

    revision: int = REVISION_DEBUG
    pkg_type: int = TYPE_PS3
    content_id: str = ""
    items: list[ItemRecord] = field(default_factory=list)
    metadata: list[MetaEntry] = field(default_factory=list)
    total_size: int = 0
    data_offset: int = 0
    data_size: int = 0
    metadata_offset: int = 0
    metadata_size: int = 0
    digest: bytes = b"\x00" * 16          # 0x60
    data_riv: bytes = b"\x00" * 16        # 0x70
    header_digest: bytes = b"\x00" * 0x40  # 0x80
    extended: Optional[ExtendedHeader] = None
    raw: bytes = b""                       # arquivo inteiro, quando lido do disco

    # ------------------------------------------------------------------ #
    # leitura
    # ------------------------------------------------------------------ #
    @staticmethod
    def parse(blob: bytes) -> "Pkg3":
        if len(blob) < HEADER_SIZE:
            raise PkgError("arquivo curto demais para ser um .pkg")
        magic = struct.unpack_from(">I", blob, 0)[0]
        if magic != MAGIC:
            raise PkgError(
                f"magic 0x{magic:08X} não é \\x7FPKG (0x{MAGIC:08X}). "
                "Se for um .pkg de PS4/PS5 use o parser ps4 (magic .CNT)."
            )
        revision, pkg_type = struct.unpack_from(">HH", blob, 4)
        meta_off, meta_count, meta_size, item_count = struct.unpack_from(">IIII", blob, 8)
        total_size, data_offset, data_size = struct.unpack_from(">QQQ", blob, 0x18)
        content_id = blob[0x30:0x54].split(b"\x00")[0].decode("ascii", "replace")
        digest = blob[0x60:0x70]
        riv = blob[0x70:0x80]
        header_digest = blob[0x80:0xC0]

        pkg = Pkg3(
            revision=revision, pkg_type=pkg_type, content_id=content_id,
            total_size=total_size, data_offset=data_offset, data_size=data_size,
            metadata_offset=meta_off, metadata_size=meta_size, digest=digest,
            data_riv=riv, header_digest=header_digest, raw=blob,
        )

        if pkg_type == TYPE_PSP_VITA and blob[0xC0:0xC4] == struct.pack(">I", EXT_MAGIC):
            pkg.extended = ExtendedHeader.unpack(blob)

        # metadata
        off = meta_off
        for _ in range(meta_count):
            if off + 8 > len(blob):
                break
            mid, msize = struct.unpack_from(">II", blob, off)
            off += 8
            pkg.metadata.append(MetaEntry(mid, blob[off:off + msize]))
            off += msize

        return pkg

    # ------------------------------------------------------------------ #
    # acesso à área cifrada
    # ------------------------------------------------------------------ #
    def meta(self, mid: int) -> Optional[MetaEntry]:
        return next((m for m in self.metadata if m.id == mid), None)

    @property
    def content_type(self) -> Optional[int]:
        entry = self.meta(0x02)
        return entry.as_int if entry else None

    def needs_key(self) -> bool:
        """True quando a área cifrada só abre com uma chave AES da Sony."""
        return self.revision == REVISION_RETAIL

    def decrypt_data(self, aes_key: Optional[bytes] = None, arcade: bool = False) -> bytes:
        """Devolve a área de dados em claro (item table + nomes + arquivos).

        * ``revision == 0x0000`` (debug/não-finalizado): keystream derivado do
          próprio ``header_digest`` -- nenhuma chave externa é necessária.
        * ``revision == 0x8000`` (retail/finalizado): AES-128-CTR com o
          contador ``data_riv``. Exige que o *usuário* forneça a chave; esta
          ferramenta não distribui nenhuma constante NPDRM.
        """
        if self.data_size <= 0:
            return b""
        blob = self.raw
        end = min(self.data_offset + self.data_size, len(blob))
        region = bytearray(blob[self.data_offset:end])

        if self.revision == REVISION_RETAIL:
            if aes_key is None:
                raise PkgError(
                    "Pacote FINALIZADO (retail): a área de dados usa AES-128-CTR com uma "
                    "constante NPDRM proprietária da Sony. Esta ferramenta não contém nem "
                    "fornece essa chave. Passe --aes-key-file <16 bytes> se você a possui "
                    "legalmente (ex.: console de desenvolvimento seu / SDK licenciado)."
                )
            if len(aes_key) != 16:
                raise PkgError("--aes-key-file precisa conter exatamente 16 bytes")
            return aes128_ctr(aes_key, self.data_riv, bytes(region))

        stream = debug_keystream(self.header_digest, len(region), arcade=arcade)
        return xor_stream(region, stream)

    def item_count_hint(self) -> int:
        """``item_count`` lido do header (offset 0x14)."""
        return struct.unpack_from(">I", self.raw, 0x14)[0] if len(self.raw) >= 0x18 else 0

    def item_table_offset(self) -> int:
        """Offset da item table dentro da área de dados.

        Em pacotes de Vita a metadata ``0x0D`` (ItemEntriesInfo) traz esse
        offset; em tudo o mais que se observa na prática ele é 0, ou seja, a
        tabela começa exatamente em ``data_offset``.
        """
        entry = self.meta(0x0D)
        if entry and len(entry.data) >= 4:
            return struct.unpack(">I", entry.data[:4])[0]
        return 0

    def open_all(self, aes_key: Optional[bytes] = None, arcade: bool = False
                 ) -> tuple[list[ItemRecord], bytes]:
        """Conveniência: decifra, monta a tabela e devolve (itens, área em claro)."""
        plain = self.decrypt_data(aes_key=aes_key, arcade=arcade)
        items: list[ItemRecord] = []
        pos = self.item_table_offset()
        for _ in range(self.item_count_hint()):
            if pos + ITEM_RECORD_SIZE > len(plain):
                break
            rec = ItemRecord.unpack(plain[pos:pos + ITEM_RECORD_SIZE])
            pos += ITEM_RECORD_SIZE
            if rec.filename_size and rec.filename_offset + rec.filename_size <= len(plain):
                raw = plain[rec.filename_offset:rec.filename_offset + rec.filename_size]
                rec.name = raw.split(b"\x00")[0].decode("utf-8", "replace")
            items.append(rec)
        self.items = items
        return items, plain

    def extract(self, item: ItemRecord, plain: bytes) -> bytes:
        return plain[item.data_offset:item.data_offset + item.data_size]

    def find_sfo(self, items: list[ItemRecord], plain: bytes) -> Optional[SFO]:
        for it in items:
            if it.name.upper().endswith("PARAM.SFO") and not it.is_dir:
                blob = self.extract(it, plain)
                if blob[:4] == b"\x00PSF":
                    return read_sfo(blob)
        return None

    # ------------------------------------------------------------------ #
    # verificação
    # ------------------------------------------------------------------ #
    def verify(self) -> dict:
        """Checagens que NÃO dependem de chave proprietária."""
        out: dict[str, object] = {"arquivo": {}, "estrutura": {}, "avisos": []}
        blob = self.raw
        warns = out["avisos"]  # type: ignore[index]

        out["arquivo"] = {  # type: ignore[index]
            "tamanho_real": len(blob),
            "total_size_no_header": self.total_size,
            "coincidem": len(blob) == self.total_size,
        }
        if len(blob) != self.total_size:
            warns.append("total_size do header não bate com o tamanho do arquivo")  # type: ignore[arg-type]

        if len(blob) >= FOOTER_SIZE:
            body, tail = blob[:-FOOTER_SIZE], blob[-FOOTER_SIZE:]
            expect = sha1(body) + b"\x00" * (FOOTER_SIZE - 20)
            out["arquivo"]["sha1_footer_ok"] = tail == expect  # type: ignore[index]
            out["arquivo"]["sha1_footer"] = tail[:20].hex()  # type: ignore[index]
            out["arquivo"]["sha1_recalculado"] = sha1(body).hex()  # type: ignore[index]

        out["estrutura"] = {  # type: ignore[index]
            "revision": f"0x{self.revision:04X}",
            "finalizado": self.revision == REVISION_RETAIL,
            "tipo": "PS3" if self.pkg_type == TYPE_PS3 else "PSP/Vita",
            "metadata_offset": self.metadata_offset,
            "metadata_size": self.metadata_size,
            "data_offset": self.data_offset,
            "data_size": self.data_size,
            "item_count": self.item_count_hint(),
            "cauda_entre_dados_e_fim": self.total_size - (self.data_offset + self.data_size),
        }
        if self.metadata_offset + self.metadata_size > self.data_offset:
            warns.append("região de metadata invade data_offset")  # type: ignore[arg-type]
        if self.data_offset + self.data_size > self.total_size:
            warns.append("data_offset+data_size ultrapassa total_size")  # type: ignore[arg-type]
        return out


# ---------------------------------------------------------------------- #
# construção
# ---------------------------------------------------------------------- #
@dataclass
class PackOptions:
    """Parâmetros de :func:`build_pkg`."""

    content_id: str
    content_type: int = 0x04          # GameData
    drm_type: int = 0x00000001
    package_type: int = 0x00000000
    title_id: str = ""
    install_directory: str = ""
    pkg_version: int = 0x00010000     # rev da ferramenta (2B) + versão (2B)
    pkg_size_override: Optional[int] = None
    platform: str = "ps3"             # "ps3" | "psp" | "vita"
    key_selector: int = 0x00          # byte 0x18 dos itens (0x90 = PSP)
    revision: int = REVISION_DEBUG
    # Material de identificação NÃO-Sony gravado no pkg_digest do header.
    # Deixar como None faz a ferramenta gerar um marcador local, deixando
    # explícito que o pacote não é assinado nem autenticado pela Sony.
    header_digest_seed: Optional[bytes] = None


def _walk(root: str) -> list[tuple[str, str, bool]]:
    """Lista (nome_interno, caminho_no_disco, é_diretório) em ordem estável."""
    entries: list[tuple[str, str, bool]] = []
    root = os.path.abspath(root)

    def rec(dirpath: str, prefix: str) -> None:
        names = sorted(os.listdir(dirpath))
        dirs = [n for n in names if os.path.isdir(os.path.join(dirpath, n))]
        files = [n for n in names if not os.path.isdir(os.path.join(dirpath, n))]
        for d in dirs:
            full = os.path.join(dirpath, d)
            entries.append((f"{prefix}{d}", full, True))
            rec(full, f"{prefix}{d}/")
        for f in files:
            entries.append((f"{prefix}{f}", os.path.join(dirpath, f), False))

    rec(root, "")
    return entries


def build_pkg(src_dir: str, opts: PackOptions) -> bytes:
    """Monta um container .pkg a partir de um diretório.

    O resultado é estruturalmente fiel ao formato NPDRM, mas **não é assinado
    pela Sony** (campo de assinatura ECDSA zerado) e, no modo padrão, usa a
    ofuscação debug derivada de um marcador local. Nenhum console retail vai
    instalá-lo -- ver ``docs/O-QUE-DA-E-O-QUE-NAO-DA.md``.
    """
    if not os.path.isdir(src_dir):
        raise PkgError(f"diretório de origem não existe: {src_dir}")
    if len(opts.content_id) > 0x24:
        raise PkgError(
            f"content_id tem {len(opts.content_id)} caracteres; o campo tem 0x24 (36). "
            "O formato é REGIAO+ID-TITLEID_00-NOME (ex.: "
            '"UP0001-NPUB30162_00-SCOTTPILGRIM0002").'
        )

    platform = opts.platform.lower()
    pkg_type = TYPE_PS3 if platform == "ps3" else TYPE_PSP_VITA

    walked = _walk(src_dir)
    if not walked:
        raise PkgError("diretório de origem está vazio")

    # ---- área de dados (texto claro, antes de ofuscar) ------------------ #
    item_table_len = _align_up(len(walked) * ITEM_RECORD_SIZE)
    names = bytearray()
    payloads: list[tuple[int, int, bytes]] = []     # (name_off, data_off, blob)
    records: list[ItemRecord] = []

    cursor = item_table_len
    name_slots: list[int] = []
    for name, _path, _is_dir in walked:
        name_slots.append(cursor)
        raw = name.encode("utf-8") + b"\x00"
        names += raw
        cursor += len(raw)
    names_blob = bytes(names)
    names_len = _align_up(len(names_blob))

    data_cursor = item_table_len + names_len
    payload_slots: list[int] = []
    blobs: list[bytes] = []
    for name, path, is_dir in walked:
        payload_slots.append(data_cursor)
        if is_dir:
            blob = b""
        else:
            with open(path, "rb") as fh:
                blob = fh.read()
        blobs.append(blob)
        data_cursor += _align_up(len(blob)) if blob else 0

    for (name, _path, is_dir), n_off, d_off, blob in zip(walked, name_slots, payload_slots, blobs):
        records.append(ItemRecord(
            filename_offset=n_off,
            filename_size=len(name.encode("utf-8")) + 1,
            data_offset=d_off,
            data_size=len(blob),
            key_selector=opts.key_selector,
            item_type=ITEM_DIR if is_dir else ITEM_FILE,
            name=name,
        ))

    region = bytearray(_align_up(data_cursor))
    for rec, blob in zip(records, blobs):
        region[rec.filename_offset:rec.filename_offset + rec.filename_size] = \
            rec.name.encode("utf-8") + b"\x00"
        if blob:
            region[rec.data_offset:rec.data_offset + len(blob)] = blob
    table = b"".join(r.pack() for r in records)
    region[0:len(table)] = table

    # ---- metadata ------------------------------------------------------- #
    pkg_size = opts.pkg_size_override if opts.pkg_size_override is not None else len(region)
    metadata = [
        MetaEntry(0x01, struct.pack(">I", opts.drm_type)),
        MetaEntry(0x02, struct.pack(">I", opts.content_type)),
        MetaEntry(0x03, struct.pack(">I", opts.package_type)),
        MetaEntry(0x04, struct.pack(">Q", pkg_size)),
        MetaEntry(0x05, struct.pack(">I", opts.pkg_version)),
    ]
    if opts.title_id:
        metadata.append(MetaEntry(0x06, opts.title_id.encode("ascii").ljust(0x0C, b"\x00")))
    metadata.append(MetaEntry(0x07, b"\x00" * 0x18))               # QA digest
    metadata.append(MetaEntry(0x08, b"\x00" * 0x08))
    metadata.append(MetaEntry(0x09, b"\x00" * 0x08))
    if opts.install_directory:
        metadata.append(MetaEntry(
            0x0A, b"\x00" * 8 + opts.install_directory.encode("ascii").ljust(0x20, b"\x00")))
    if platform in ("psp", "vita"):
        item_info = struct.pack(">II", 0, len(region)) + sha256(bytes(region))
        metadata.append(MetaEntry(0x0D, item_info))

    meta_blob = b"".join(m.pack() for m in metadata)
    meta_off = HEADER_SIZE if pkg_type == TYPE_PS3 else 0x280
    meta_size = _align_up(len(meta_blob))
    data_offset = _align_up(meta_off + meta_size)

    # ---- header --------------------------------------------------------- #
    total_size = data_offset + len(region) + TAIL_DIGEST_SIZE + FOOTER_SIZE
    content_id = opts.content_id.encode("ascii").ljust(0x24, b"\x00")

    header = bytearray(HEADER_SIZE)
    struct.pack_into(">IHH", header, 0x00, MAGIC, opts.revision, pkg_type)
    struct.pack_into(">IIII", header, 0x08, meta_off, len(metadata), meta_size, len(records))
    struct.pack_into(">QQQ", header, 0x18, total_size, data_offset, len(region))
    header[0x30:0x54] = content_id
    header[0x60:0x70] = sha1(bytes(region))[:16]           # digest local
    header[0x70:0x80] = b"\x00" * 16                       # data_riv (inútil em debug)

    # pkg_digest em 0x80: cmac(0x10) + assinatura ECDSA(0x28) + sha1(0x08).
    # O cmac é um MARCADOR LOCAL derivado do content_id; não é um AES-CMAC
    # NPDRM. A assinatura fica zerada: não temos (nem teremos) a chave
    # privada da Sony.
    seed = opts.header_digest_seed or sha256(b"pkgforge|" + opts.content_id.encode("ascii"))
    cmac_local = sha256(seed)[:16]
    header[0x80:0x90] = cmac_local
    header[0x90:0xB8] = b"\x00" * 0x28                      # assinatura: zerada
    header[0xB8:0xC0] = sha1(bytes(header[0x00:0x80]))[-8:]

    out = bytearray()
    out += header
    if pkg_type == TYPE_PSP_VITA:
        ext = ExtendedHeader(
            pkg_key_id=0x00000001 if platform == "psp" else 0xC0000002,
            metadata_header_hmac_offset=data_offset - 16 if data_offset >= 16 else 0,
        )
        pad = bytearray(data_offset - HEADER_SIZE)
        pad[0:EXT_HEADER_SIZE] = ext.pack()
        from .crypto import pkg_hmac
        pad[0x40:0x50] = pkg_hmac(bytes(header) + bytes(pad[0:EXT_HEADER_SIZE]))
        pad[0x50:0x60] = pkg_hmac(meta_blob.ljust(meta_size, b"\x00"))
        out += bytes(pad)
    else:
        out += meta_blob.ljust(meta_size, b"\x00")
        out += b"\x00" * (data_offset - len(out))

    assert len(out) == data_offset, (len(out), data_offset)

    # ---- ofuscação da área de dados ------------------------------------- #
    if opts.revision == REVISION_DEBUG:
        stream = debug_keystream(bytes(header[0x80:0xC0]), len(region))
        out += xor_stream(region, stream)
    else:
        # retail sem chave => gravamos a área em claro e avisamos. Isso NÃO
        # instala em lugar nenhum; existe só para inspeção do layout.
        out += bytes(region)

    out += b"\x00" * TAIL_DIGEST_SIZE
    out += sha1(bytes(out)) + b"\x00" * (FOOTER_SIZE - 20)

    if len(out) != total_size:
        raise PkgError(f"bug interno: tamanho {len(out)} != total_size {total_size}")
    return bytes(out)
