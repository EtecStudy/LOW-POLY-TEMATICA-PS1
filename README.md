# LOW-POLY-TEMATICA-PS1

Ferramental do projeto **low-poly temática PS1**.

## `tools/pkgforge` — containers `.pkg`

Inspetor e gerador de pacotes NPDRM (PS3/PSP/Vita), CNT (PS4) e FIH (PS5) em
Python puro, **sem dependências externas e sem chaves da Sony**.

```bash
cd tools/pkgforge
python3 -m pkgforge.cli info    jogo.pkg --json
python3 -m pkgforge.cli verify  jogo.pkg
python3 -m pkgforge.cli unpack  jogo.pkg ./saida
python3 -m pkgforge.cli pack    ./conteudo saida.pkg --content-id 'UP0001-NPUB30162_00-LOWPOLYTEMATICA1'
python3 -m unittest discover -s tests -v
```

Documentação:

* [`tools/pkgforge/docs/PKG-FORMAT.md`](tools/pkgforge/docs/PKG-FORMAT.md) —
  referência byte a byte dos três formatos (header, metadata, item table,
  cifragem, footer).
* [`tools/pkgforge/docs/O-QUE-DA-E-O-QUE-NAO-DA.md`](tools/pkgforge/docs/O-QUE-DA-E-O-QUE-NAO-DA.md) —
  **leia primeiro**: o que é possível gerar, o que exige criptografia privada da
  Sony, e por que `.pkg` não é o caminho para rodar um jogo de PS1.

### Limitação importante, em uma frase

O `pkgforge` lê qualquer `.pkg` e escreve containers estruturalmente fiéis, mas
**não produz pacotes instaláveis em console** — isso exige a constante AES
NPDRM + assinatura ECDSA (PS3/PSP/Vita) ou o EKPFS de PFS (PS4/PS5), material
privado da Sony que não está neste repositório e não deve ser adicionado.

Para *rodar* conteúdo de PS1, o caminho sem chaves é a imagem de disco
(`.bin`/`.cue`) construída com [`mkpsxiso`](https://github.com/Lameguy64/mkpsxiso).

## Estrutura

```
tools/pkgforge/     # inspetor/gerador de .pkg + docs + testes
README.md
```
