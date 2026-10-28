# O que dá e o que não dá para fazer com `.pkg`

Resposta direta à pergunta "você consegue criar arquivos pkg?": **o container,
sim; um pacote que um console instale, não.** Este documento explica o motivo
técnico, sem rodeio.

---

## 1. O que o `pkgforge` FAZ

| Capacidade | Status |
|---|---|
| Ler e descrever header NPDRM (`\x7FPKG`) de PS3/PSP/Vita | ✅ completo |
| Ler e descrever header CNT (`\x7FCNT`) de PS4 | ✅ completo |
| Detectar FIH (`\x7FFIH`) de PS5 | ✅ detecção (parser completo: não) |
| Listar metadata (ContentType, DRMType, TitleID, InstallDirectory…) | ✅ |
| **Extrair** pacotes *não-finalizados* (debug) de PS3/PSP/Vita | ✅ sem nenhuma chave |
| **Extrair** entradas em texto claro de pacotes PS4 (`param.sfo`, `playgo-*`, nomes) | ✅ sem nenhuma chave |
| Ler/escrever `PARAM.SFO` | ✅ |
| **Gerar** um `.pkg` NPDRM estruturalmente fiel (header, metadata, item table, footer SHA-1) | ✅ |
| Recalcular e conferir digests e footer | ✅ |
| Round-trip `pack → info → verify → unpack` idêntico byte a byte | ✅ coberto por testes |

Isso é suficiente para: estudar o formato, inspecionar pacotes que você possui,
ferramentas internas de build, fixtures de teste, validação de pipeline.

## 2. O que o `pkgforge` NÃO FAZ (e por quê)

Todo `.pkg` **instalável** depende de material criptográfico privado da Sony.
Não existe contorno de formato — o bloqueio é matemático:

### 2.1 Retail / finalizado (`pkg_revision = 0x8000`)

A área de dados é cifrada em **AES-128-CTR** com uma constante NPDRM da Sony
(`npdrm_pkg_ps3_aes_key` e variantes por plataforma). O header carrega ainda uma
**assinatura ECDSA** verificada contra a chave pública embutida no firmware.

→ Sem a constante AES **e** sem a chave privada ECDSA, é impossível produzir um
pacote retail válido. **Duas** portas fechadas.

### 2.2 Debug / não-finalizado (`pkg_revision = 0x0000`)

Aqui está a pegadinha que muita gente não percebe: o keystream de dados é
derivado dos **16 primeiros bytes do `pkg_header_digest`** — e esses 16 bytes
são um **AES-CMAC calculado com a mesma constante NPDRM da Sony**.

Ou seja, o modo debug **não** é uma rota "sem chave". O `pkgforge` consegue:

* **ler** qualquer pacote debug existente (o keystream está todo no arquivo); ✅
* **escrever** um pacote debug autoconsistente, com um marcador local no lugar
  do CMAC. ✅ para testes — ❌ para consoles: o CMAC não confere.

### 2.3 PS4 / PS5 (`fPKG`)

O conteúdo vive numa imagem **PFS** cifrada com **XTS-AES-128**, cuja chave vem
do **EKPFS**, mais árvore de Merkle e assinatura. Os "fake PKGs" que circulam
dependem das chaves de desenvolvimento/debug de PFS extraídas de consoles SDK.

→ O `pkgforge` **não** monta PFS e **não** gera fPKG.

### 2.4 Sobre chaves vazadas

Constantes AES NPDRM, EKPFS debug e `klicensee` circulam na internet.
**Este repositório não as contém, não as baixa e não tem onde você colá-las
embutidas.** O único ponto de entrada é `--aes-key-file`, que exige que *você*
forneça um arquivo de 16 bytes — pensado para quem tem chave própria por via
legítima (SDK licenciado, console de desenvolvimento seu). Nada é hard-coded.

---

## 3. E o console com HEN?

Vale separar as coisas, porque "HEN" não significa o mesmo nas três gerações:

**PS3 (HEN/PS3Xploit)** — habilita o instalador de pacotes oficial. Ele espera
pacotes com criptografia e assinatura legítimas. O que a cena homebrew distribui
para HEN normalmente **não** é `.pkg` fabricado em casa: são pacotes que já
passaram pelo fluxo oficial, ou homebrew em formato que não exige assinatura
NPDRM. Não há como o `pkgforge` produzir algo que o instalador do HEN aceite.

**PS4 (HEN/GoldHEN)** — instala **fPKG**, que exige as chaves debug de PFS.
Fora do escopo desta ferramenta, pelas razões acima e porque o uso típico é
instalar dumps de jogos comerciais.

**PS Vita (HENkaku/h-encore)** — usa `.vpk`, um formato **diferente** de `.pkg`
(arquivo plano, sem PFS, sem cifragem obrigatória). Esse sim é factível sem
chaves da Sony, e é o caminho real para homebrew de Vita. Não está implementado
aqui, mas é um próximo passo honesto se for o seu alvo.

---

## 4. Para o *seu* projeto (PS1 low-poly), o caminho que funciona

Se o objetivo é **jogar/rodar** o resultado deste repositório, `.pkg` é a rota
errada. Um jogo de PS1 não precisa de assinatura nenhuma — ele vai num **CD**:

```
seu jogo (PS-EXE + assets)
        │  mkpsxiso + iso.xml
        ▼
   game.bin / game.cue   ← roda em DuckStation, PCSX-Redux, ePSXe,
                            PS2, PS3 (via emulador), PS1 com modchip/tonyhax
```

O `mkpsxiso` foi compilado e validado neste ambiente (clone do GitHub + CMake,
gerou um `MODE2/2352` íntegro). Ele **não** depende de nenhuma chave da Sony:
um CD de PS1 tem apenas a *license string* no lead-in, e homebrew contorna isso
com emulador, modchip ou freePS1boot.

Se você quiser "empacotar" os assets do jogo num arquivo `.pkg` **seu**, com
formato próprio (não o da Sony), aí sim dá para fazer 100% — e o
`tools/pkgforge` pode servir de base estrutural para isso.

---

## 5. Uso legítimo

* Inspecionar e extrair pacotes **que você possui** ou de domínio homebrew.
* Gerar fixtures e containers para tooling/testes seus.
* Estudar o formato.

Fora disso — produzir pacotes para instalar conteúdo comercial de terceiros —
é violação de DRM e pirataria, e não é algo em que eu vá ajudar.
