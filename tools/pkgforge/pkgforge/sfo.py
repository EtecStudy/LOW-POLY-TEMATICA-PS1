"""Leitor/escritor de PARAM.SFO (little-endian).

Layout:

    0x00 u32 magic          0x00505346 ("\\0PSF")
    0x04 u32 version        0x00000101
    0x08 u32 key_table_off
    0x0C u32 data_table_off
    0x10 u32 pairs_count
    0x14 ...                pairs_count entradas de 0x10 bytes:
        u16 key_offset      (relativo à tabela de chaves)
        u16 param_fmt       (0x0004 binário, 0x0104 UTF-8, 0x0102 u32)
        u32 param_length    (bytes usados)
        u32 param_maxlen    (bytes reservados)
        u32 data_offset     (relativo à tabela de dados)
"""

from __future__ import annotations

import struct
from collections import OrderedDict

MAGIC = b"\x00PSF"     # os 4 primeiros bytes do arquivo, nesta ordem
MAGIC_U32_BE = 0x00505346
VERSION = 0x00000101

FMT_BIN = 0x0004      # bytes crus / string UTF-8 terminada em NUL
FMT_UTF8 = 0x0104     # string UTF-8 terminada em NUL
FMT_INT32 = 0x0102    # inteiro de 32 bits little-endian

FMT_NAMES = {FMT_BIN: "bin", FMT_UTF8: "utf8", FMT_INT32: "int32"}

__all__ = ["SFO", "read_sfo", "write_sfo", "MAGIC", "FMT_BIN", "FMT_UTF8", "FMT_INT32"]


class SFO:
    """Tabela ordenada de chave -> (formato, valor)."""

    def __init__(self) -> None:
        self.entries: "OrderedDict[str, tuple[int, object]]" = OrderedDict()

    # -- construção ------------------------------------------------------- #
    def set_str(self, key: str, value: str, fmt: int = FMT_UTF8) -> "SFO":
        self.entries[key] = (fmt, value)
        return self

    def set_int(self, key: str, value: int) -> "SFO":
        self.entries[key] = (FMT_INT32, int(value))
        return self

    def set_bin(self, key: str, value: bytes) -> "SFO":
        self.entries[key] = (FMT_BIN, bytes(value))
        return self

    def get(self, key: str, default=None):
        item = self.entries.get(key)
        return default if item is None else item[1]

    def __contains__(self, key: str) -> bool:
        return key in self.entries

    # -- serialização ----------------------------------------------------- #
    def dumps(self) -> bytes:
        # O firmware espera as chaves em ordem alfabética (ordem da tabela).
        items = sorted(self.entries.items(), key=lambda kv: kv[0])

        index = bytearray()
        key_table = bytearray()
        data_table = bytearray()

        for key, (fmt, value) in items:
            if fmt == FMT_INT32:
                raw = struct.pack("<I", value & 0xFFFFFFFF)
                length = maxlen = 4
            elif isinstance(value, (bytes, bytearray)):
                raw = bytes(value)
                length = len(raw)
                maxlen = max(length, 4)
            else:
                text = str(value).encode("utf-8")
                raw = text + b"\x00"
                length = len(raw)
                maxlen = length

            index += struct.pack("<HHIII", len(key_table), fmt, length, maxlen, len(data_table))
            key_table += key.encode("utf-8") + b"\x00"
            data_table += raw

        header_size = 0x14
        key_off = header_size + len(index)
        data_off = key_off + len(key_table)
        out = MAGIC + struct.pack("<IIII", VERSION, key_off, data_off, len(items))
        return out + bytes(index) + bytes(key_table) + bytes(data_table)


def read_sfo(data: bytes) -> SFO:
    if len(data) < 0x14:
        raise ValueError("PARAM.SFO curto demais")
    if data[:4] != MAGIC:
        raise ValueError(f"magic inválida: {data[:4]!r} (esperado {MAGIC!r})")
    version, key_off, data_off, count = struct.unpack_from("<IIII", data, 4)
    if version not in (VERSION, 0x00000100):
        # Não é fatal: versões antigas existem por aí.
        pass
    if key_off >= len(data) or data_off >= len(data):
        raise ValueError("offsets de tabela apontam para fora do arquivo")

    sfo = SFO()
    for i in range(count):
        k_off, fmt, length, _maxlen, d_off = struct.unpack_from("<HHIII", data, 0x14 + i * 0x10)
        key = data[key_off + k_off:data.index(b"\x00", key_off + k_off)].decode("utf-8", "replace")
        blob = data[data_off + d_off:data_off + d_off + length]
        if fmt == FMT_INT32:
            sfo.entries[key] = (fmt, struct.unpack("<I", blob[:4].ljust(4, b"\x00"))[0])
        elif fmt == FMT_UTF8:
            sfo.entries[key] = (fmt, blob.rstrip(b"\x00").decode("utf-8", "replace"))
        else:
            sfo.entries[key] = (fmt, blob)
    return sfo


def write_sfo(sfo: SFO) -> bytes:
    return sfo.dumps()
