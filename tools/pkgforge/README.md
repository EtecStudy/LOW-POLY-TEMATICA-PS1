# pkgforge

Inspetor e gerador de containers `.pkg` das plataformas PlayStation —
**sem dependências externas** (Python 3.8+, só stdlib) e **sem nenhuma chave
proprietária da Sony**.

```
tools/pkgforge/
├── pkgforge/
│   ├── crypto.py   # SHA-1/256, PKG HMAC, keystream debug, AES-128 puro (FIPS-197)
│   ├── sfo.py      # PARAM.SFO: leitura e escrita
│   ├── ps3.py      # NPDRM (\x7FPKG): header, metadata, item table, build/unpack
│   ├── ps4.py      # CNT (\x7FCNT): header, entradas, PFS (só leitura)
│   └── cli.py      # interface de linha de comando
├── tests/          # 18 testes (unittest), incluindo round-trip completo
└── docs/
    ├── PKG-FORMAT.md               # referência byte a byte dos três formatos
    └── O-QUE-DA-E-O-QUE-NAO-DA.md  # limites reais: o que instala e o que não instala
```

> **Leia `docs/O-QUE-DA-E-O-QUE-NAO-DA.md` antes de usar.** Resumo: esta
> ferramenta lê qualquer `.pkg` e gera containers estruturalmente fiéis, mas
> **não produz pacotes instaláveis** em console — isso exige criptografia
> privada da Sony (constante AES NPDRM + ECDSA em PS3/PSP/Vita; EKPFS em
> PS4/PS5), que não está aqui e não pode ser embutida.

## Uso

```bash
cd tools/pkgforge

# descrever um pacote (detecta NPDRM x CNT x FIH sozinho)
python3 -m pkgforge.cli info   jogo.pkg
python3 -m pkgforge.cli info   jogo.pkg --json --hexdump 0x100

# conferir footer SHA-1 e consistência estrutural
python3 -m pkgforge.cli verify jogo.pkg

# extrair (pacote debug de PS3/PSP/Vita: sem chave; PS4: entradas em texto claro)
python3 -m pkgforge.cli unpack jogo.pkg ./saida

# gerar um container a partir de um diretório
python3 -m pkgforge.cli pack ./conteudo saida.pkg \
    --content-id 'UP0001-NPUB30162_00-LOWPOLYTEMATICA1' \
    --title-id NPUB30162 --install-directory NPUB30162

# PARAM.SFO
python3 -m pkgforge.cli mk-sfo PARAM.SFO --title 'Low Poly Temática' \
    --title-id NPUB30162 --category HG --set BOOTABLE=1
python3 -m pkgforge.cli sfo PARAM.SFO --json
```

## Testes

```bash
cd tools/pkgforge && python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

Cobrem: vetor oficial AES-128 do FIPS-197, auto-inversão do keystream debug,
round-trip de `PARAM.SFO`, layout do header gerado (offsets, cauda `0x60`,
`total_size`), footer SHA-1, round-trip de conteúdo com subdiretórios,
ofuscação real da área de dados, extended header `.ext` de PSP/Vita, detecção
de formato e o fluxo completo pela CLI.

## Opções de `pack`

| Opção | Default | Significado |
|---|---|---|
| `--content-id` | *obrigatório* | 36 chars, `REGIAO+ID-TITLEID_00-NOME` |
| `--platform` | `ps3` | `ps3` (metadata em 0xC0) ou `psp`/`vita` (emits `.ext`, metadata em 0x280) |
| `--revision` | `debug` | `debug` (0x0000, ofuscado) ou `retail` (0x8000, **sem** cifragem real) |
| `--content-type` | `0x04` | `0x04` GameData, `0x06` **PS1emu**, `0x07` PSP, `0x09` Theme… |
| `--psp-key` | off | marca os itens com `key_selector = 0x90` (chave PSP) |
| `--title-id` / `--install-directory` | vazio | metadata 0x06 / 0x0A |
| `--quiet` | off | não imprime o aviso de "não instalável" |

## O que `--aes-key-file` é (e o que não é)

`unpack` de um pacote **finalizado** (`revision 0x8000`) precisa da constante
AES NPDRM. A ferramenta **não a contém**: em vez disso, falha com uma mensagem
explicando o porquê. Se você possui legitimamente uma chave de 16 bytes (SDK
licenciado, console de desenvolvimento seu), passe-a como arquivo ou hex:

```bash
python3 -m pkgforge.cli unpack jogo.pkg ./saida --aes-key-file minha_chave.bin
```

Nenhuma chave é gravada, enviada ou cacheada.

## Licença

Mesma licença do repositório. O formato descrito em `docs/PKG-FORMAT.md` é
documentação pública; as constantes criptográficas da Sony não fazem parte
deste projeto e não devem ser adicionadas a ele.
