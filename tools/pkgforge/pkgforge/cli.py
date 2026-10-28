"""Interface de linha de comando do pkgforge.

    python3 -m pkgforge info    ARQUIVO [--json]
    python3 -m pkgforge verify  ARQUIVO
    python3 -m pkgforge unpack  ARQUIVO DESTINO [--aes-key-file K] [--arcade]
    python3 -m pkgforge pack    ORIGEM SAIDA --content-id ID [opções]
    python3 -m pkgforge sfo     ARQUIVO [--json]
    python3 -m pkgforge mk-sfo  SAIDA --title T --title-id ID [--category C]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

from . import __version__
from .ps3 import (CONTENT_TYPE_NAMES, ITEM_TYPE_NAMES, PackOptions, Pkg3,
                  PkgError, REVISION_DEBUG, REVISION_RETAIL, TYPE_PS3, build_pkg)
from .ps4 import PS4_CONTENT_TYPES, PS4_DRM_TYPES, Pkg4, Pkg4Error, detect
from .sfo import FMT_NAMES, SFO, read_sfo

AVISO_NAO_INSTALAVEL = """\
=============================================================================
 AVISO: este .pkg NÃO É INSTALÁVEL em nenhum console PlayStation.

 Um pacote instalável exige material criptográfico privado da Sony:
   * retail (revisão 0x8000): AES-128-CTR com a constante NPDRM + assinatura
     ECDSA com a chave privada da Sony;
   * debug  (revisão 0x0000): o AES-CMAC do pkg_digest do header é derivado
     da MESMA constante NPDRM, e o keystream de dados sai dele;
   * PS4/PS5 fPKG: EKPFS/chaves debug de PFS + assinatura.

 O pkgforge NÃO contém, NÃO baixa e NÃO aceita embutir nenhuma dessas chaves.
 Ele produz um container estruturalmente fiel ao formato, autoconsistente
 (round-trip pack -> unpack -> verify), útil para tooling, testes e estudo do
 formato. Leia docs/O-QUE-DA-E-O-QUE-NAO-DA.md.
============================================================================="""


def _hex(blob: bytes, base: int = 0, width: int = 16) -> str:
    linhas = []
    for off in range(0, len(blob), width):
        chunk = blob[off:off + width]
        hexa = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        linhas.append(f"{base + off:08X}  {hexa:<{width * 3 - 1}}  |{asc}|")
    return "\n".join(linhas)


def _read_key_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        raw = fh.read()
    raw = raw.strip()
    if len(raw) == 32:
        try:
            return bytes.fromhex(raw.decode("ascii"))
        except ValueError:
            pass
    return raw


# ---------------------------------------------------------------------- #
# info
# ---------------------------------------------------------------------- #
def _info_ps3(pkg: Pkg3) -> dict:
    dados: dict = {
        "formato": "NPDRM (PS3/PSP/Vita)",
        "magic": "\\x7FPKG",
        "revision": f"0x{pkg.revision:04X}",
        "finalizado_retail": pkg.revision == REVISION_RETAIL,
        "tipo": "PS3" if pkg.pkg_type == TYPE_PS3 else "PSP/Vita",
        "content_id": pkg.content_id,
        "total_size": pkg.total_size,
        "data_offset": pkg.data_offset,
        "data_size": pkg.data_size,
        "metadata_offset": pkg.metadata_offset,
        "metadata_size": pkg.metadata_size,
        "item_count": pkg.item_count_hint(),
        "digest_0x60": pkg.digest.hex(),
        "data_riv_0x70": pkg.data_riv.hex(),
        "header_digest_0x80": pkg.header_digest.hex(),
        "precisa_de_chave_sony": pkg.needs_key(),
    }
    if pkg.extended:
        e = pkg.extended
        dados["extended_header"] = {
            "pkg_key_id": f"0x{e.pkg_key_id:08X}",
            "ext_hdr_size": e.ext_hdr_size,
            "ext_data_size": e.ext_data_size,
            "tail_offset": e.tail_offset,
            "hmac_main_and_ext": e.hmac_main_and_ext.hex(),
            "hmac_metadata": e.hmac_metadata.hex(),
        }
    metas = []
    for m in pkg.metadata:
        item: dict = {"id": f"0x{m.id:02X}", "nome": m.name, "tamanho": len(m.data)}
        if m.id in (0x01, 0x02, 0x03, 0x05):
            val = m.as_int
            item["valor"] = f"0x{val:X}" if val is not None else None
            if m.id == 0x02 and val is not None:
                item["significado"] = CONTENT_TYPE_NAMES.get(val, "?")
        elif m.id == 0x04:
            item["valor"] = m.as_int
        elif m.id == 0x06:
            item["valor"] = m.data.split(b"\x00")[0].decode("ascii", "replace")
        elif m.id == 0x0A:
            item["valor"] = m.data[8:].split(b"\x00")[0].decode("ascii", "replace")
        else:
            item["valor"] = m.data.hex()
        metas.append(item)
    dados["metadata"] = metas
    return dados


def _info_ps4(pkg: Pkg4) -> dict:
    return {
        "formato": "CNT (PS4/PS5)",
        "magic": "\\x7FCNT",
        "content_id": pkg.content_id,
        "drm_type": f"0x{pkg.drm_type:X} ({PS4_DRM_TYPES.get(pkg.drm_type, '?')})",
        "content_type": f"0x{pkg.content_type:X} ({PS4_CONTENT_TYPES.get(pkg.content_type, '?')})",
        "pkg_flags": f"0x{pkg.pkg_flags:08X}",
        "entry_count": pkg.entry_count,
        "file_count": pkg.file_count,
        "table_offset": f"0x{pkg.table_offset:X}",
        "body_offset": pkg.body_offset,
        "body_size": pkg.body_size,
        "pfs_image_offset": pkg.pfs_image_offset,
        "pfs_image_size": pkg.pfs_image_size,
        "pfs_signed_size": pkg.pfs_signed_size,
        "pfs_cache_size": pkg.pfs_cache_size,
        "pkg_size": pkg.pkg_size,
        "entradas": [
            {
                "id": f"0x{e.id:04X}",
                "nome": e.name or e.known_name,
                "flags1": f"0x{e.flags1:08X}",
                "flags2": f"0x{e.flags2:08X}",
                "offset": e.offset,
                "size": e.size,
                "cifrada": e.encrypted,
                "key_index": e.key_index,
            }
            for e in pkg.entries
        ],
        "pfs_legivel_sem_chave": False,
        "motivo": ("A imagem PFS usa XTS-AES-128 com chave derivada do EKPFS do "
                   "pacote (debug: chaves da Sony). Sem elas só as entradas em "
                   "texto claro são acessíveis."),
    }


def cmd_info(args: argparse.Namespace) -> int:
    with open(args.arquivo, "rb") as fh:
        blob = fh.read()
    kind = detect(blob)
    if kind == "ps3":
        dados = _info_ps3(Pkg3.parse(blob))
    elif kind == "ps4":
        dados = _info_ps4(Pkg4.parse(blob))
    elif kind == "ps5-fih":
        dados = {"formato": "FIH (PS5 finalized image)",
                 "nota": "wrapper \\x7FFIH; contém um CNT embutido. Parser completo não implementado."}
    else:
        print("arquivo não é um .pkg reconhecido (nem \\x7FPKG nem \\x7FCNT)", file=sys.stderr)
        return 2
    if args.hexdump:
        dados["hexdump"] = _hex(blob[:args.hexdump])
    if args.json:
        print(json.dumps(dados, indent=2, ensure_ascii=False))
    else:
        _print_dict(dados)
    return 0


def _print_dict(d: dict, indent: int = 0) -> None:
    pad = "  " * indent
    for k, v in d.items():
        if isinstance(v, dict):
            print(f"{pad}{k}:")
            _print_dict(v, indent + 1)
        elif isinstance(v, list):
            print(f"{pad}{k}: ({len(v)})")
            for item in v:
                if isinstance(item, dict):
                    resumo = ", ".join(f"{ik}={iv}" for ik, iv in item.items())
                    print(f"{pad}  - {resumo}")
                else:
                    print(f"{pad}  - {item}")
        else:
            print(f"{pad}{k}: {v}")


# ---------------------------------------------------------------------- #
# verify
# ---------------------------------------------------------------------- #
def cmd_verify(args: argparse.Namespace) -> int:
    with open(args.arquivo, "rb") as fh:
        blob = fh.read()
    kind = detect(blob)
    if kind == "ps3":
        rel = Pkg3.parse(blob).verify()
    elif kind == "ps4":
        rel = Pkg4.parse(blob).verify()
    else:
        print("formato não reconhecido", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(rel, indent=2, ensure_ascii=False))
    else:
        _print_dict(rel)
    avisos = rel.get("avisos") if isinstance(rel, dict) else None
    return 1 if avisos else 0


# ---------------------------------------------------------------------- #
# unpack
# ---------------------------------------------------------------------- #
def cmd_unpack(args: argparse.Namespace) -> int:
    with open(args.arquivo, "rb") as fh:
        blob = fh.read()
    kind = detect(blob)
    os.makedirs(args.destino, exist_ok=True)

    if kind == "ps4":
        pkg = Pkg4.parse(blob)
        escritos, pulados = 0, 0
        for e in pkg.entries:
            if e.encrypted:
                pulados += 1
                continue
            blob_e = pkg.entry_bytes(e.id)
            if blob_e is None:
                continue
            nome = e.name or e.known_name
            caminho = os.path.join(args.destino, nome.replace("/", os.sep))
            os.makedirs(os.path.dirname(caminho) or args.destino, exist_ok=True)
            with open(caminho, "wb") as fh:
                fh.write(blob_e)
            escritos += 1
        sfo = pkg.read_sfo()
        if sfo:
            with open(os.path.join(args.destino, "PARAM.SFO.json"), "w", encoding="utf-8") as fh:
                json.dump({k: v[1] if v[0] != 0x0004 else v[1].hex()
                           for k, v in sfo.entries.items()}, fh, indent=2, ensure_ascii=False)
        print(f"PS4: {escritos} entradas em texto claro extraídas, {pulados} cifradas ignoradas.")
        if pulados:
            print("As entradas cifradas precisam das entry keys (derivadas do EKPFS).",
                  file=sys.stderr)
        return 0

    if kind != "ps3":
        print("formato não reconhecido", file=sys.stderr)
        return 2

    pkg = Pkg3.parse(blob)
    key = _read_key_file(args.aes_key_file) if args.aes_key_file else None
    plain = pkg.decrypt_data(aes_key=key, arcade=args.arcade)
    items, _ = pkg.open_all(aes_key=key, arcade=args.arcade)
    if not items:
        print("nenhum item encontrado na tabela", file=sys.stderr)
        return 1

    for rec in items:
        nome = rec.name or f"item_0x{rec.data_offset:08X}"
        caminho = os.path.join(args.destino, nome.replace("/", os.sep))
        if rec.is_dir:
            os.makedirs(caminho, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(caminho) or args.destino, exist_ok=True)
        with open(caminho, "wb") as fh:
            fh.write(pkg.extract(rec, plain))
        print(f"  {rec.item_type:>3} {ITEM_TYPE_NAMES.get(rec.item_type, '?'):<16} "
              f"{rec.data_size:>10}  {nome}")

    sfo = pkg.find_sfo(items, plain)
    if sfo:
        with open(os.path.join(args.destino, "PARAM.SFO.json"), "w", encoding="utf-8") as fh:
            json.dump({k: (v[1].hex() if isinstance(v[1], bytes) else v[1])
                       for k, v in sfo.entries.items()}, fh, indent=2, ensure_ascii=False)
    print(f"{len(items)} itens extraídos em {args.destino}")
    return 0


# ---------------------------------------------------------------------- #
# pack
# ---------------------------------------------------------------------- #
def cmd_pack(args: argparse.Namespace) -> int:
    revision = REVISION_RETAIL if args.revision == "retail" else REVISION_DEBUG
    opts = PackOptions(
        content_id=args.content_id,
        content_type=int(args.content_type, 0),
        drm_type=int(args.drm_type, 0),
        package_type=int(args.package_type, 0),
        title_id=args.title_id or "",
        install_directory=args.install_directory or "",
        pkg_version=int(args.pkg_version, 0),
        platform=args.platform,
        key_selector=0x90 if args.psp_key else 0x00,
        revision=revision,
    )
    blob = build_pkg(args.origem, opts)
    with open(args.saida, "wb") as fh:
        fh.write(blob)
    print(f"gravado {args.saida} ({len(blob)} bytes, {len(blob) // 1024} KiB)")
    if not args.quiet:
        print(AVISO_NAO_INSTALAVEL, file=sys.stderr)
    return 0


# ---------------------------------------------------------------------- #
# sfo
# ---------------------------------------------------------------------- #
def cmd_sfo(args: argparse.Namespace) -> int:
    with open(args.arquivo, "rb") as fh:
        blob = fh.read()
    sfo = read_sfo(blob)
    dados = {
        k: {"fmt": FMT_NAMES.get(v[0], f"0x{v[0]:04X}"),
            "valor": v[1].hex() if isinstance(v[1], bytes) else v[1]}
        for k, v in sfo.entries.items()
    }
    if args.json:
        print(json.dumps(dados, indent=2, ensure_ascii=False))
    else:
        _print_dict(dados)
    return 0


def cmd_mk_sfo(args: argparse.Namespace) -> int:
    sfo = SFO()
    sfo.set_str("TITLE", args.title)
    sfo.set_str("TITLE_ID", args.title_id)
    sfo.set_str("VERSION", args.version)
    sfo.set_str("CATEGORY", args.category)
    sfo.set_int("BOOTABLE", 1)
    sfo.set_int("PARENTAL_LEVEL", 1)
    sfo.set_str("PS3_SYSTEM_VER", "04.9000")
    sfo.set_str("APP_VER", args.version)
    for extra in args.set or []:
        if "=" not in extra:
            print(f"--set precisa de CHAVE=VALOR (recebi {extra!r})", file=sys.stderr)
            return 2
        k, v = extra.split("=", 1)
        try:
            sfo.set_int(k, int(v, 0))
        except ValueError:
            sfo.set_str(k, v)
    with open(args.saida, "wb") as fh:
        fh.write(sfo.dumps())
    print(f"gravado {args.saida} ({os.path.getsize(args.saida)} bytes)")
    return 0


# ---------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pkgforge",
        description="Inspetor/gerador de containers .pkg (NPDRM e CNT) sem chaves da Sony.",
    )
    p.add_argument("--version", action="version", version=f"pkgforge {__version__}")
    sub = p.add_subparsers(dest="comando", required=True)

    s = sub.add_parser("info", help="descreve um .pkg")
    s.add_argument("arquivo")
    s.add_argument("--json", action="store_true")
    s.add_argument("--hexdump", type=lambda x: int(x, 0), default=0,
                   help="mostra N primeiros bytes em hexdump")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("verify", help="confere footer SHA-1 e consistência estrutural")
    s.add_argument("arquivo")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("unpack", help="extrai itens de um .pkg")
    s.add_argument("arquivo")
    s.add_argument("destino")
    s.add_argument("--aes-key-file", default=None,
                   help="arquivo com 16 bytes (ou hex) da chave AES; só é necessário "
                        "para pacotes FINALIZADOS (retail). A ferramenta não fornece chave.")
    s.add_argument("--arcade", action="store_true",
                   help="usa a derivação de pacotes arcade (ex.: Namco System 357)")
    s.set_defaults(func=cmd_unpack)

    s = sub.add_parser("pack", help="monta um container .pkg a partir de um diretório")
    s.add_argument("origem")
    s.add_argument("saida")
    s.add_argument("--content-id", required=True,
                   help='ex.: "UP0001-NPUB00000_00-LOWPOLYTEMATICA001"')
    s.add_argument("--title-id", default="")
    s.add_argument("--install-directory", default="")
    s.add_argument("--content-type", default="0x04", help="default 0x04 (GameData)")
    s.add_argument("--drm-type", default="0x01")
    s.add_argument("--package-type", default="0x00")
    s.add_argument("--pkg-version", default="0x00010000")
    s.add_argument("--platform", choices=("ps3", "psp", "vita"), default="ps3")
    s.add_argument("--revision", choices=("debug", "retail"), default="debug")
    s.add_argument("--psp-key", action="store_true",
                   help="marca os itens com key_selector 0x90 (chave PSP)")
    s.add_argument("--quiet", action="store_true", help="não imprime o aviso")
    s.set_defaults(func=cmd_pack)

    s = sub.add_parser("sfo", help="lê um PARAM.SFO")
    s.add_argument("arquivo")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_sfo)

    s = sub.add_parser("mk-sfo", help="gera um PARAM.SFO mínimo")
    s.add_argument("saida")
    s.add_argument("--title", required=True)
    s.add_argument("--title-id", required=True)
    s.add_argument("--version", default="01.00")
    s.add_argument("--category", default="HG",
                   help="HG=HDD game, DG=disc game, PP=patch, PE=PS1 emu, 2P=PS2 emu")
    s.add_argument("--set", action="append", metavar="CHAVE=VALOR",
                   help="campo extra; valor numérico vira int32")
    s.set_defaults(func=cmd_mk_sfo)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (PkgError, Pkg4Error) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"erro: arquivo não encontrado: {exc.filename}", file=sys.stderr)
        return 1
    except IsADirectoryError as exc:
        print(f"erro: esperado um arquivo, veio um diretório: {exc.filename}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"erro: sem permissão: {exc.filename}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
