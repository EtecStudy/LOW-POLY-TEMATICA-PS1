# Plano: reprodutor de DVD no PS4 via app `.pkg` — análise de viabilidade

**Veredito: não fecha.** Não por dificuldade de programação, mas porque o plano
esbarra em três bloqueios independentes — e um deles torna o projeto redundante.

Data da análise: 2026-10-27.

---

## 0. O bloqueio que vem antes de todos: já existe

O PS4 **já reproduz DVD-Video e Blu-ray nativamente**. É um recurso do sistema,
não um app da Store:

* Insere o disco → o ícone aparece na *content area* → Play.
* Exige **ativação única pela internet** na primeira vez; depois funciona offline.
* Formatos: DVD-ROM, DVD±R/RW (**finalizados**), AVCHD em DVD, BD-ROM, BD-R/RE.
* **Não** reproduz: CD de áudio, DVD-Audio, Ultra HD Blu-ray (nem no Pro),
  discos não finalizados, e **não** usa drive óptico USB externo para filmes.
* O app "Media Player" **não** é o caminho para disco físico — ele só lê
  arquivos de vídeo em USB ou servidor DLNA.

Ou seja: o produto que o plano propõe construir já vem de fábrica, com licença
CSS/AACS resolvida pela Sony e suporte a menus de DVD. Qualquer reprodutor
homebrew seria estritamente pior.

> Se a motivação real for "meu PS4 não está reproduzindo DVD", isso é
> troubleshooting (ativação pendente, região, disco não finalizado, drive),
> não um projeto de software. Ver `#5`.

---

## 1. Muro 1 — acesso ao drive não existe para homebrew

Mesmo com GoldHEN (que dá acesso nível-CFW em memória, instalação de fPKG,
FTP, etc.):

* Não há API de homebrew para ler setores arbitrários de um disco inserido.
  O drive é atendido pelo *Disc Player* do sistema; jogos em disco usam o
  formato proprietário de disco do PS4 (SFFS/PFS de disco).
* Inserir um DVD **lança o player da Sony**, não o seu app. Não há como um app
  de usuário se registrar como handler de disco.
* Chegar ao dispositivo exigiria engenharia reversa de kernel não documentada —
  um projeto de pesquisa em si, sem garantia de sucesso.

## 2. Muro 2 — DVD-Video é cifrado com CSS

O conteúdo de um DVD-Video comercial (os `VIDEO_TS/*.VOB`) é protegido por
**CSS (Content Scramble System)**. Para decifrar é preciso:

* as *player keys* licenciadas pela DVD CCA, ou
* um decifrador não licenciado (DeCSS/libdvdcss), cuja distribuição é
  juridicamente contestada em várias jurisdições.

A Sony licencia isso para o Disc Player dela. Um app homebrew não tem como
obter essas chaves por via legítima, e eu não vou distribuir nem apontar para
chaves vazadas. **Este muro existe mesmo que o Muro 1 seja resolvido.**

## 3. Muro 3 — empacotar como `.pkg` instalável

Já documentado em `tools/pkgforge/docs/O-QUE-DA-E-O-QUE-NAO-DA.md`:

* Um app PS4 instalável é um **fPKG**, que depende das chaves debug de PFS
  (EKPFS) extraídas de consoles SDK — material proprietário vazado.
* O `pkgforge` **não** monta imagem PFS e **não** gera fPKG, por decisão.
* Sem isso, não há `.pkg` que o PS4 aceite instalar.

## 4. A observação interessante: BD-J (e por que ela também não resolve)

Existe **um** caminho documentado para rodar código próprio a partir de um disco
num PS4 **sem jailbreak**: o **BD-J** (Blu-ray Disc Java), parte da especificação
Blu-ray. É exatamente por ele que funciona o exploit BD-JB.

Por que ainda assim não serve para o plano:

| Aspecto | Realidade |
|---|---|
| Mídia | **Só Blu-ray.** O BD-JB não funciona com DVD nem CD — é um exploit do *player de Blu-ray*. Exige gravador de BD-R. |
| Sandbox | BD-J é uma máquina Java restrita: sem acesso a setores crus do drive, sem CSS, sem ler DVD. |
| Escopo | Serve para conteúdo interativo de Blu-ray (menus, extras, rede), não para player de DVD. |
| Firmware | Depende da versão do sistema; é um vetor de exploit, não uma plataforma estável de desenvolvimento. |

Conclusão: BD-J responde "dá para rodar meu código de um disco no PS4?" com
*sim*, e responde "dá para fazer um reprodutor de DVD assim?" com **não**.

---

## 4b. "Mas fizeram o PS4 rodar PS2, PS1, PSP… por que DVD é difícil?"

Pergunta justa, e a resposta dissolve a aparente contradição. **Nenhum desses
feitos usa o leitor de disco.** Todos consomem **arquivos** (`.iso`, `.bin`,
`.chd`) ripados antes, num PC. O drive óptico nunca entra no circuito.

A comunidade diz isso explicitamente: *"mesmo com um PS4 destravado você não
pode simplesmente colocar um disco de PS1/PS2 e jogar — não funciona assim."*

### O mecanismo real

1. **O emulador não está no firmware do PS4.** Segundo a PSDevWiki, os
   emuladores *não* vêm pré-instalados no SO do PS4: cada título oficial
   "PS2 Classics on PS4" **carrega sua própria cópia do emulador**, assinada
   pela Sony.
2. A cena **extraiu esse emulador** dos pkgs oficiais de PS2 Classics.
3. E o **reempacotou** junto com o `.iso` de qualquer jogo — ferramentas como
   PS1-FPKG / PS2-FPKG / PSP-FPKG (Jabu) e PS-Classics-fPKG-Builder (SvenGDK).
4. O pacote resultante é um **fPKG**, instalado em console destravado.

Ou seja: não é "vencer o DRM do drive". É **reaproveitar um emulador que a
própria Sony escreveu** e religá-lo a um arquivo de disco. A leitura de disco
é emulada em software — o emulador finge ser o drive.

### Onde está a diferença entre eles e o `pkgforge`

No **passo 4**. Todo esse fluxo termina em fPKG, que depende das chaves debug
de PFS (EKPFS) vazadas de consoles SDK. É exatamente o passo que esta
ferramenta se recusa a fazer. Não é diferença de habilidade — é diferença de
decisão sobre material proprietário vazado.

### A exceção que confirma a regra: PS5SX2 / PS4SX2

Em outubro de 2026 o dev *Sword* lançou o **PS5SX2**, um port nativo do PCSX2
que **lê DVDs físicos de PS2** num PS5 destravado (e existe o PS4SX2 derivado).
Isso prova que acesso cru ao drive **é** alcançável com homebrew de kernel.

Mas repare no que ele lê: **discos de jogo de PS2**, que são DVD-ROM **sem
CSS**. Um DVD-Video de filme é outro animal — o conteúdo (`VIDEO_TS/*.VOB`) é
embaralhado com CSS e exige *player keys* licenciadas pela DVD CCA.

| | Disco de jogo PS2 | DVD-Video (filme) |
|---|---|---|
| Mídia | DVD-ROM | DVD-ROM |
| Cifragem do conteúdo | **nenhuma** | **CSS** |
| Acesso cru ao drive resolve? | **Sim** | **Não** — falta a chave |

**É por isso que "ler disco de PS2" foi resolvido e "tocar DVD de filme por
homebrew" não.** Não é preguiça da cena: é uma camada de DRM que só a Sony
licenciou.

### E "PS5 rodando jogo de Xbox"?

Não encontrei evidência de que isso exista. O RetroArch de PS4/PS5 cobre NES,
SNES, Game Boy/Color/Advance, Genesis/Mega Drive, Master System, Game Gear,
Sega CD, SG-1000, arcade (FBNeo), PS2 (LRPS2), PSP (PPSSPP) e GameCube/Wii
(Dolphin). **Nenhum core de Xbox** — nem do Xbox original, muito menos 360.
Se você viu isso em algum lugar, era emulação rodando em PC, não num PS5.

---

## 5. Se o objetivo real for outro, os caminhos que funcionam

O plano parece querer uma destas quatro coisas. Cada uma tem rota própria:

### A. "Quero assistir DVD no meu PS4"
Não precisa de software. Conecta na internet uma vez, insere o DVD, ativa o
recurso, pronto. Se falhar: confira região do disco × região do console,
finalização do disco gravado, atualização de sistema, e teste com um DVD
comercial para isolar se o problema é o drive.

### B. "Quero um reprodutor com estética PS1/low-poly meu"
**Totalmente factível, e combina com este repositório.** Um player com UI
low-poly temática PS1 (vertex snapping, affine texture warping, dithering,
paleta limitada) rodando em PC/navegador, reproduzindo arquivos de vídeo.
Nenhuma chave de ninguém, nenhum DRM, e é o tipo de coisa que dá para mostrar.

### C. "Quero homebrew rodando num console PlayStation de verdade"
* **PS Vita** → `.vpk`. Formato plano, sem PFS, sem cifragem obrigatória, e o
  HENkaku/h-encore instala sem chaves da Sony. É o caminho homebrew mais limpo
  que existe. (Ressalva: Vita não tem drive de DVD.)
* **PS3 com CFW** → homebrew instalado sem o fluxo NPDRM oficial, e o PS3
  **reproduz DVD nativamente** também. Acesso a `/dev_bdvd` existe para
  homebrew de PS3. Ainda assim, CSS continua sendo problema para DVD-Video
  comercial.
* **PS1/PS2** → o caminho sem chave nenhuma é imagem de disco (`mkpsxiso` →
  `.bin`/`.cue`), já validado neste ambiente.

### D. "Quero estudar o formato `.pkg`"
É o que `tools/pkgforge` já faz: leitura completa, extração do que não depende
de chave, geração de containers fiéis ao formato, 21 testes.

---

## 6. Referências

* PlayStation Support — *Play video and music from discs and USB drives*
  (ativação única, formatos de DVD/BD suportados, drive USB externo não serve
  para filmes): <https://www.playstation.com/en-us/support/hardware/play-video-music-discs-usb-drives/>
* PlayStation Support (JP) — discos reproduzíveis no PS4 (CD não é suportado):
  <https://www.playstation.com/ja-jp/support/hardware/ps4-view-cd-bd-dvd/>
* PlayStation Support — *PS4 Media Player* (USB/DLNA, não disco físico):
  <https://www.playstation.com/en-us/support/hardware/ps-media-player/>
* ConsoleMods Wiki — *PS4:BD-JB* (exploit exige Blu-ray gravado; não DVD):
  <https://consolemods.org/wiki/PS4:BD-JB>
* ConsoleMods Wiki — *PS4:FAQ* (GoldHEN/Mira dão acesso nível-CFW em memória,
  resetam a cada reboot): <https://consolemods.org/wiki/PS4:FAQ>
* PSDevWiki — *PS2 Emulation* ("emuladores não vêm pré-instalados no SO do PS4;
  precisam ser extraídos de um pkg oficial de PS2 Classics assinado pela Sony"):
  <https://www.psdevwiki.com/ps4/PS2_Emulation>
* PSDevWiki — *PS2 Classics Emulator Compatibility List*:
  <https://www.psdevwiki.com/ps4/PS2_Classics_Emulator_Compatibility_List>
* ConsoleMods Wiki — *PS4:PS-FPKG* (PS1/PS2/PSP-FPKG de Jabu: empacotam
  emulador + configs + ISO para consoles explorados):
  <https://consolemods.org/wiki/PS4:PS-FPKG>
* GameBrew — *PS2-FPKG PS4* (converte ISO/BIN em fPKG usando os emuladores de
  PS2 Classics): <https://www.gamebrew.org/wiki/PS2-FPKG_PS4>
* SvenGDK — *PS-Classics-fPKG-Builder* (PS1/PS2/PSP para PS4/PS5):
  <https://github.com/SvenGDK/PS-Classics-fPKG-Builder>
* Yahoo Tech — *Homebrew Dev Brings PS2 Disc Support to Jailbroken PS5s*
  (PS5SX2, port nativo do PCSX2 que lê DVDs físicos de PS2):
  <https://tech.yahoo.com/gaming/articles/homebrew-dev-brings-ps2-disc-155321187.html>
* iHaiDeeZ — *PS4SX2* (PCSX2 nativo em PS4 destravado; requer console que
  instale fake packages, BIOS própria e jogos em .iso/.chd/.cso/.zso):
  <https://github.com/iHaiDeeZ/PS4SX2>
* matschi95 — *RommPS* (lista de sistemas cobertos pelo RetroArch em PS4/PS5;
  não inclui Xbox): <https://github.com/matschi95/RommPS>
* r/ps4homebrew — *Uses for a jail broken PS4* ("mesmo destravado, não dá para
  colocar um disco de PS1/PS2 e jogar"):
  <https://www.reddit.com/r/ps4homebrew/comments/is8nyt/uses_for_a_jail_broken_ps4/>
