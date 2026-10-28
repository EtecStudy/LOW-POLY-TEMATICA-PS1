# O formato `.pkg` — referência byte a byte

Este documento descreve os containers de pacote das plataformas PlayStation.
Tudo aqui vem de documentação pública (PSDevWiki) e de implementações abertas
(pkg2zip, `PkgUnpack.cpp` do PPSSPP, LibOrbisPkg, LibProsperoPKG).
Nenhuma chave proprietária da Sony aparece neste documento nem no código.

Existem três famílias de `.pkg`, que **não são intercambiáveis**:

| Família | Magic | Plataformas | Header |
|---|---|---|---|
| NPDRM | `\x7FPKG` (`0x7F504B47`) | PS3, PSP, PS Vita, PSM | `0xC0` |
| CNT | `\x7FCNT` (`0x7F434E54`) | PS4 (e base do PS5) | `0x1000` |
| FIH | `\x7FFIH` (`0x7F464948`) | PS5 (finalized image) | `0x10000` |

---

## 1. NPDRM (`\x7FPKG`) — PS3 / PSP / PS Vita

### 1.1 Mapa do arquivo

```
+0x000  header            0xC0 bytes, texto claro
+0x0C0  extended header   0x40 bytes, texto claro (SÓ PSP/Vita)
+0x100  hashes / assinaturas
+0x280  metadata          texto claro (offset e contagem vêm do header)
  ...
+data_offset              ÁREA CIFRADA: item table, nomes, conteúdo dos arquivos
-0x40   pkg_digest de cauda
-0x20   SHA-1 do arquivo inteiro menos os últimos 0x20 bytes
```

Em PS3 a metadata costuma começar em `0xC0`; em PSP/Vita, em `0x280` (depois do
extended header e da região de hashes).

### 1.2 Header (0xC0, tudo big-endian)

| Campo | Off | Tam | Notas |
|---|---|---|---|
| `magic` | 0x00 | 4 | `7F 50 4B 47` = `\x7FPKG` |
| `pkg_revision` | 0x04 | 2 | `0x8000` = **finalizado/retail**; `0x0000` = **não-finalizado/debug** |
| `pkg_type` | 0x06 | 2 | `0x0001` = PS3, `0x0002` = PSP/Vita |
| `metadata_offset` | 0x08 | 4 | `0xC0` (PS3) ou `0x280` (PSP/Vita) |
| `metadata_count` | 0x0C | 4 | nº de entradas de metadata |
| `metadata_size` | 0x10 | 4 | `0xC0` (PS3/PSP), `0x160` (Vita) |
| `item_count` | 0x14 | 4 | arquivos + diretórios dentro da área cifrada |
| `total_size` | 0x18 | 8 | tamanho total do `.pkg` |
| `data_offset` | 0x20 | 8 | início da área cifrada |
| `data_size` | 0x28 | 8 | tamanho da área cifrada |
| `content_id` | 0x30 | 0x24 | 36 chars, ex. `UP0001-NPUB30162_00-SCOTTPILGRIM0002` |
| *padding* | 0x54 | 0x0C | |
| `digest` | 0x60 | 0x10 | SHA-1 dos arquivos/atributos, mesclado |
| `pkg_data_riv` | 0x70 | 0x10 | bloco contador AES-128-CTR (retail) |
| `pkg_header_digest` | 0x80 | 0x40 | `pkg_digest` do header (abaixo) |

```c
typedef struct {              // 0x40 bytes, em 0x80
  u8 cmac_hash[0x10];         // AES-CMAC -- depende de constante NPDRM da Sony
  u8 npdrm_signature[0x28];   // assinatura ECDSA (R,S) do header
  u8 sha1_hash[0x8];          // últimos 8 bytes de um SHA-1
} pkg_digest;
```

> **Ponto crítico:** `cmac_hash` é calculado com a constante AES NPDRM da Sony.
> E, em pacotes *debug*, o keystream dos dados é derivado **desse mesmo campo**
> (ver 1.5). Ou seja: sem a constante da Sony não se produz nem um retail nem um
> debug que um console aceite. Detalhes em `O-QUE-DA-E-O-QUE-NAO-DA.md`.

### 1.3 Extended header (PSP/Vita, 0x40 em 0xC0)

```c
typedef struct {
  u32 magic;                             // 0x7F657874 "\x7Fext"
  u32 unknown_1;                         // sempre 1
  u32 ext_hdr_size;                      // ex.: 0x40
  u32 ext_data_size;                     // ex.: 0x180
  u32 main_and_ext_headers_hmac_offset;  // ex.: 0x100
  u32 metadata_header_hmac_offset;       // ex.: 0x360 / 0x390 / 0x490
  u64 tail_offset;                       // tipicamente 0x1A0
  u32 padding1;
  u32 pkg_key_id;                        // em +0x24 (= +0xE4 no arquivo)
                                         // PSP=0x1, Vita=0xC0000002, PSM=0xC0000004
  u32 full_header_hmac_offset;           // 0 em pacotes antigos
  u8  padding2[0x14];
} PKG_EXT_HEADER;
```

Os HMACs apontados são calculados com o algoritmo "PKG HMAC" (dois SHA-1
encadeados com um buffer intermediário de 64 bytes, retornando 16 bytes) —
implementado em `crypto.pkg_hmac`.

### 1.4 Metadata

Sequência plana de registros `u32 id`, `u32 size`, `u8 value[size]`:

| id | Nome | Tam | Conteúdo |
|---|---|---|---|
| 0x01 | DRMType | 4 | tipo de DRM NPDRM |
| 0x02 | ContentType | 4 | ver tabela abaixo |
| 0x03 | PackageType / PackageFlag | 4 | patch, demo, key, flags de diretório… |
| 0x04 | PackageSize | 8 | tamanho do pacote |
| 0x05 | ToolRevision + PkgVersion | 4 | 2 bytes revisão do `make_package_npdrm` + 2 bytes versão |
| 0x06 | TitleID | 0x0C | ex. `NPEG00005` (PSP) |
| 0x07 | QADigest | 0x18 | digest de QA |
| 0x08 / 0x09 / 0x0B / 0x0C | unk | 8 | não documentado |
| 0x0A | InstallDirectory | 0x28 | 8 bytes zerados + diretório |
| 0x0D | ItemEntriesInfo | 0x28 | **Vita**: offset + size da item table + SHA-256 |
| 0x0E | SFOInfo | 0x38 | **Vita**: offset/size do `PARAM.SFO` + `PSP2_SYSTEM_VER` + SHA-256 |
| 0x0F | UnknownDataInfo | 0x48 | **Vita** |
| 0x10 | EntiretyInfo | 0x38 | **Vita**: offset/size da tabela de digests + flags + SHA-256 |
| 0x11 | PublishingToolsVersion | 0x28 | versão das Publishing Tools + PFSBuilder |
| 0x12 | SelfInfo | 0x38 | **Vita** |

**ContentType** (id 0x02) — os relevantes para este repositório:

| Valor | Nome | Instala em |
|---|---|---|
| 0x04 | GameData | `/dev_hdd0/game/` |
| 0x05 | GameExec | `/dev_hdd0/game/` |
| **0x06** | **PS1emu** | `/dev_hdd0/game/` (PS3), `ux0:pspemu/PSP/GAME/` (Vita) |
| 0x07 | PSP | `/dev_hdd0/game/`, `ms0:PSP/GAME/` |
| 0x09 | Theme | `/dev_hdd0/theme` |
| 0x0F | minis | `/dev_hdd0/game/` |
| 0x11 | VMC | `/dev_hdd0/tmp/vmc/` |
| 0x15 / 0x16 | PSP2GD / PSP2AC | `ux0:app/`, `ux0:addcont/` |
| 0x1A / 0x1B / 0x1E | PS4GD / PS4AC / PS4DP | `/user/app/`, `/user/addcont/` |

`0x06 PS1emu` é o tipo usado pelos **PS1 Classics** de PSN — o conteúdo é um
`EBOOT.PBP` (PBP envolvendo a ISO do PS1) mais `ISO.BIN.EDAT`. Ver 1.7.

### 1.5 Área cifrada e tabela de itens

Dentro de `data_offset` vem, nesta ordem: **item table → nomes → conteúdo**.
Todos os offsets dos registros são **relativos a `data_offset`** e alinhados a 16.

```c
typedef struct {                  // 0x20 bytes, big-endian
  u32 filename_offset;            // 0x00
  u32 filename_size;              // 0x04  (inclui o NUL terminador)
  u64 data_offset;                // 0x08
  u64 data_size;                  // 0x10
  u8  key_selector;               // 0x18  0x90 => chave PSP
  u8  padding[2];                 // 0x19
  u8  item_type;                  // 0x1B
  u32 padding;                    // 0x1C
} PKG_ITEM_RECORD;
```

Os 4 bytes em 0x18 lidos como `u32` big-endian dão `flags`, e
`(flags >> 0x1C) & 7` é o **índice da chave AES** do item. Isso permite que um
mesmo pacote use chaves diferentes por item — em updates de PSP, `PBOOT.PBP` e
os dados de patch levam `0x90` enquanto `PARAM.SFO`, ícones, diretórios e
`ISO.BIN.EDAT` usam a chave PS3.

`item_type` (byte 0x1B):

| Valor | Significado | Conteúdo começa com |
|---|---|---|
| 2 | NPDRM EDAT | `NPD\0` (só `ISO.BIN.EDAT`) |
| 3 | arquivo comum | o que for (PNG, `\0PSF`…) |
| 4 | diretório | — |
| 5 | PSP EDAT (PGD) | `\0PSPEDAT` |
| 8 | PSP EDAT (PRX/`.sprx`) | `\0PSPEDAT` |
| 11 | PBP | `\0PBP` |

**Desofuscação — dois regimes distintos:**

*Retail / finalizado (`pkg_revision == 0x8000`)*: AES-128-CTR cobrindo toda a
área a partir de `data_offset`, com contador inicial `pkg_data_riv` (0x70)
incrementado a cada 16 bytes. A chave é a constante NPDRM da plataforma
(`npdrm_pkg_ps3_aes_key` etc.). **Constante proprietária — não incluída aqui.**

*Não-finalizado / debug (`pkg_revision == 0x0000`)*: keystream derivado do
próprio `pkg_header_digest` (0x80), sem chave externa:

```c
key[0x00:0x08] = header_digest[0x00:0x08];
key[0x08:0x10] = header_digest[0x00:0x08];
key[0x10:0x18] = arcade ? header_digest[0x00:0x08] : header_digest[0x08:0x10];
key[0x18:0x20] = header_digest[0x08:0x10];
if (arcade) memset(key + 0x20, 0xA0, 0x18);      // ex.: Namco System 357
bfr = sha1(key);                                  // usa os 16 primeiros bytes
for (i = 0; i < size; i++) {
    if (i != 0 && (i % 16) == 0) { be64(key + 0x38) += 1; bfr = sha1(key); }
    data[offset + i] ^= bfr[i & 0xf];
}
```

Implementado em `crypto.debug_keystream`. Isso permite **ler** pacotes debug
existentes sem nenhuma chave. Mas note que os 16 bytes de entrada são o
`cmac_hash` — que num pacote legítimo só a Sony sabe produzir.

### 1.6 Footer

Os últimos `0x20` bytes são `SHA1(arquivo[:-0x20])` seguido de 12 bytes zerados.
É o que `pkgforge verify` recalcula.

### 1.7 O caso específico de PS1 (relevante para este repositório)

Um **PS1 Classic** de PSN é um `.pkg` com `ContentType = 0x06 (PS1emu)` contendo:

* `EBOOT.PBP` — um PBP que envolve a ISO do PS1 (`DATA.PSP`) mais `KEYS.BIN`;
* `ISO.BIN.EDAT` — container EDAT (`NPD\0`) que, uma vez decifrado, carrega o
  `klicensee` **daquele título específico**;
* `PARAM.SFO`, `ICON0.PNG`, `PIC0.PNG`, `PIC1.PNG`, `DOCUMENT.DAT`.

Duas camadas de segredo da Sony estão no caminho: a chave comum do
`ISO.BIN.EDAT` **e** o `klicensee` por título (que também é o que amarra a
licença à conta PSN). Sem elas o pacote não autentica. É por isso que
"transformar minha ISO de PS1 num pkg instalável" não é um problema de formato —
é um problema de chave que este repositório não resolve, e não deve tentar.

---

## 2. CNT (`\x7FCNT`) — PS4

Header de `0x1000` bytes, big-endian, seguido da tabela de entradas e do corpo.

| Campo | Off | Tam |
|---|---|---|
| `pkg_magic` | 0x000 | 4 = `0x7F434E54` |
| `pkg_flags` / type | 0x004 | 4 |
| *unk* | 0x008 | 4 |
| `pkg_file_count` | 0x00C | 4 |
| `pkg_entry_count` | 0x010 | 4 |
| `pkg_sc_entry_count` | 0x014 | 2 |
| `pkg_entry_count_2` | 0x016 | 2 (igual a `entry_count`) |
| `pkg_table_offset` | 0x018 | 4 |
| `pkg_entry_data_size` | 0x01C | 4 |
| `pkg_body_offset` | 0x020 | 8 |
| `pkg_body_size` | 0x028 | 8 |
| `pkg_content_offset` | 0x030 | 8 |
| `pkg_content_size` | 0x038 | 8 |
| `pkg_content_id` | 0x040 | 0x24 |
| `pkg_drm_type` | 0x070 | 4 |
| `pkg_content_type` | 0x074 | 4 |
| `pkg_content_flags` | 0x078 | 4 |
| `pkg_promote_size` | 0x07C | 4 |
| `pkg_version_date` / `pkg_version_hash` | 0x080 / 0x084 | 4 / 4 |
| `pkg_iro_tag` | 0x098 | 4 |
| `pkg_drm_type_version` | 0x09C | 4 |
| `digest_entries1` / `2` | 0x100 / 0x120 | 0x20 cada |
| `digest_table_digest` | 0x140 | 0x20 |
| `digest_body_digest` | 0x160 | 0x20 |
| `pfs_image_count` | 0x404 | 4 |
| `pfs_image_flags` | 0x408 | 8 |
| `pfs_image_offset` / `_size` | 0x410 / 0x418 | 8 / 8 |
| `mount_image_offset` / `_size` | 0x420 / 0x428 | 8 / 8 |
| `pkg_size` | 0x430 | 8 |
| `pfs_signed_size` / `pfs_cache_size` | 0x438 / 0x43C | 4 / 4 |
| `pfs_image_digest` / `pfs_signed_digest` | 0x440 / 0x460 | 0x20 cada |
| `pkg_digest` | 0xFE0 | 0x20 |

### 2.1 Tabela de entradas (0x20 cada, big-endian)

```c
typedef struct {
  uint32_t id;               // ID conhecido (ver abaixo)
  uint32_t filename_offset;  // offset na tabela de nomes (entrada 0x200)
  uint32_t flags1;           // bit 0x80000000 = entrada CIFRADA
  uint32_t flags2;           // índice da chave de cifragem
  uint32_t offset;           // offset no arquivo
  uint32_t size;
  uint64_t padding;
} pkg_table_entry;
```

IDs principais: `0x0010` entry keys, `0x0020` image key, `0x0080` general
digests, `0x0100` metas, `0x0200` **tabela de nomes** (texto claro),
`0x0400` `license.dat`, `0x0401` `license.info`, `0x0402` `nptitle.dat`,
`0x0403` `npbind.dat`, `0x1000` **`param.sfo`** (texto claro), `0x1001`
`playgo-chunk.dat`, `0x1002` `playgo-chunk.sha`, `0x1003` `playgo-manifest.xml`,
`0x1004`/`0x1005` `pronunciation.xml`/`.sig`, `0x1006`–`0x1009` imagens.

### 2.2 PFS

O grosso do pacote é a **imagem PFS**: um sistema de arquivos próprio
(superbloco, inodes `di_d32`/`di_s32`, dirents), contendo internamente um
`pfs_image.dat` comprimido (cabeçalho `PFSC`) onde moram `sce_sys/`, `eboot.bin`
e os dados do jogo. É cifrada com **XTS-AES-128** em blocos de `0x1000`, com
chave derivada por HMAC-SHA256 do **EKPFS** do pacote usando o *crypt seed* em
`+0x370` do próprio PFS, e protegida por uma árvore de Merkle SHA-256.

Sem o EKPFS (retail: `license.dat` + chave do console; debug: chave de
desenvolvimento da Sony) a imagem PFS não abre. Por isso o `pkgforge` só **lê**
pacotes PS4, extraindo as entradas que já estão em texto claro.

---

## 3. FIH (`\x7FFIH`) — PS5

O *finalized image* de PS5 envolve um CNT. Header little-endian de `0x10000`
bytes (offset da imagem PFS em `0x10`, CNT embutido em `0x58`/`0xA0`), byte
assinado em `0x05` (`0x00` debug, `0x80` retail). O `pkgforge` apenas detecta
essa magic e reporta; parser completo não implementado.

---

## 4. Fontes

* PSDevWiki — *PKG files* (PS3): <https://www.psdevwiki.com/ps3/PKG_files>
* PSDevWiki — *PKG files* (PS4): <https://www.psdevwiki.com/ps4/PKG_files>
* PSDevWiki — *PFS*, *ISO.BIN.EDAT*, *Content ID*
* pkg2zip (mmozeiko) — leitura de pacotes PSP/Vita
* PPSSPP `Core/Util/PkgUnpack.cpp` — semântica de `flags` da item table
* LibOrbisPkg (Maxton) / LibProsperoPKG (SvenGDK) — CNT de PS4/PS5
