"""Primitivas criptográficas usadas pelo formato .pkg.

Nada aqui contém chaves proprietárias da Sony. Os algoritmos são os
documentados publicamente (PSDevWiki / implementações homebrew):

  * ``pkg_hmac``   - o "HMAC" SHA-1 truncado do extended header (PSP/Vita).
  * ``debug_keystream`` - o ofuscamento de pacotes *não finalizados* (debug),
    cuja chave é derivada do campo ``pkg_header_digest`` do próprio arquivo.
  * ``AES128``     - AES-128 puro em Python, usado SOMENTE quando o usuário
    fornece explicitamente uma chave (--aes-key-file). A constante
    ``npdrm_pkg_*_aes_key`` NÃO é distribuída por esta ferramenta.
"""

from __future__ import annotations

import hashlib
from typing import Iterable

__all__ = [
    "sha1",
    "sha256",
    "pkg_hmac",
    "debug_keystream",
    "xor_stream",
    "AES128",
    "aes128_ctr",
]


def sha1(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def pkg_hmac(data: bytes) -> bytes:
    """Hash de 16 bytes usado nos HMACs do extended header (PSP/PS Vita).

    Implementação idêntica à publicada na PSDevWiki: dois SHA-1 encadeados com
    um buffer intermediário de 64 bytes montado a partir de fatias do primeiro
    digest, retornando os 16 primeiros bytes do segundo SHA-1.
    """
    sha = sha1(data)
    buf = bytearray(64)
    buf[0:8] = sha[4:12]
    buf[8:16] = buf[0:8]
    buf[16:20] = sha[12:16]
    buf[20] = sha[16]
    buf[21] = sha[1]
    buf[22] = sha[2]
    buf[23] = sha[3]
    buf[24:32] = buf[16:24]
    return sha1(bytes(buf))[:16]


def debug_keystream(header_digest: bytes, size: int, arcade: bool = False) -> Iterable[int]:
    """Gera o keystream de um pacote *não finalizado* (pkg_revision == 0x0000).

    ``header_digest`` são os 0x40 bytes em 0x80 do cabeçalho (``pkg_digest``).
    Somente os 16 primeiros bytes (``cmac_hash``) alimentam a derivação.

    Importante: num pacote debug legítimo esses 16 bytes são um AES-CMAC
    calculado com a constante NPDRM da Sony. Sem essa constante é impossível
    produzir um pacote debug que um console aceite -- daí este keystream servir
    para *ler* pacotes debug existentes e para criar containers
    autoconsistentes, não para criar pacotes instaláveis.
    """
    if len(header_digest) < 16:
        raise ValueError("header_digest precisa de pelo menos 16 bytes")

    key = bytearray(0x40)
    key[0x00:0x08] = header_digest[0x00:0x08]
    key[0x08:0x10] = header_digest[0x00:0x08]
    key[0x10:0x18] = header_digest[0x00:0x08] if arcade else header_digest[0x08:0x10]
    key[0x18:0x20] = header_digest[0x08:0x10]
    if arcade:
        key[0x20:0x38] = b"\xa0" * 0x18
    # key[0x38:0x40] = contador de bloco (big-endian), começa em 0

    block = sha1(bytes(key))[:16]
    counter = 0
    for i in range(size):
        if i and (i % 16) == 0:
            counter += 1
            key[0x38:0x40] = counter.to_bytes(8, "big")
            block = sha1(bytes(key))[:16]
        yield block[i & 0xF]


def xor_stream(data: bytes | bytearray, stream: Iterable[int]) -> bytes:
    """XOR de ``data`` com um keystream (usado para cifrar/decifrar).

    Não modifica o buffer de entrada: devolve sempre um ``bytes`` novo, o que
    torna a operação auto-inversa quando o mesmo keystream é reaplicado.
    """
    out = bytearray(data)
    for i, k in enumerate(stream):
        if i >= len(out):
            break
        out[i] ^= k
    return bytes(out)


# --------------------------------------------------------------------------- #
# AES-128 em Python puro (FIPS-197). Só entra em ação com chave fornecida.
# --------------------------------------------------------------------------- #

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

_RCON = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _mul(a: int, b: int) -> int:
    """Multiplicação em GF(2^8)."""
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        b >>= 1
        a = _xtime(a)
    return out & 0xFF


class AES128:
    """AES-128 em modo ECB (bloco único). CTR é montado em cima dele."""

    BLOCK = 16
    ROUNDS = 10

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("AES128 exige chave de 16 bytes")
        self._rk = self._expand_key(key)

    @staticmethod
    def _expand_key(key: bytes) -> list[list[int]]:
        words = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
        for i in range(4, 44):
            temp = list(words[i - 1])
            if i % 4 == 0:
                temp = temp[1:] + temp[:1]                    # RotWord
                temp = [_SBOX[b] for b in temp]                 # SubWord
                temp[0] ^= _RCON[i // 4]
            words.append([words[i - 4][j] ^ temp[j] for j in range(4)])
        # 11 round keys de 16 bytes
        return [
            [b for w in words[r * 4:r * 4 + 4] for b in w]
            for r in range(11)
        ]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("bloco deve ter 16 bytes")
        # state em column-major, como no FIPS-197
        s = [block[i] for i in range(16)]

        def add_round_key(rk: list[int]) -> None:
            for i in range(16):
                s[i] ^= rk[i]

        add_round_key(self._rk[0])
        for rnd in range(1, self.ROUNDS + 1):
            for i in range(16):                                # SubBytes
                s[i] = _SBOX[s[i]]
            # ShiftRows: linha r desloca r posições à esquerda (índice = r + 4c)
            for r in range(1, 4):
                row = [s[r + 4 * c] for c in range(4)]
                row = row[r:] + row[:r]
                for c in range(4):
                    s[r + 4 * c] = row[c]
            if rnd != self.ROUNDS:                             # MixColumns
                for c in range(4):
                    a = s[4 * c:4 * c + 4]
                    s[4 * c + 0] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
                    s[4 * c + 1] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
                    s[4 * c + 2] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
                    s[4 * c + 3] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)
            add_round_key(self._rk[rnd])
        return bytes(s)


def aes128_ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-128-CTR: keystream = ECB(key, iv + índice_do_bloco).

    É o modo usado nos pacotes *finalizados* (retail) de PS3/PSP: o contador
    de 128 bits começa em ``pkg_data_riv`` e é incrementado como um inteiro
    big-endian a cada bloco de 16 bytes.
    """
    cipher = AES128(key)
    counter = int.from_bytes(iv, "big")
    out = bytearray(len(data))
    for off in range(0, len(data), 16):
        ks = cipher.encrypt_block(counter.to_bytes(16, "big"))
        chunk = data[off:off + 16]
        out[off:off + len(chunk)] = bytes(a ^ b for a, b in zip(chunk, ks))
        counter = (counter + 1) & ((1 << 128) - 1)
    return bytes(out)
