# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

## [Não lançado]

### Corrigido
- **Orientação do Frida em emulador (`frida.py`, `report.py`):** o relatório e as
  notas mandavam `frida -U Gadget -l ...`, que trava em emulador conectado via
  `adb connect` (não aparece como device USB). Agora recomendam `adb forward` +
  `frida -H 127.0.0.1:27042 Gadget -l ...`, que funciona em emulador adb-TCP e em USB.
- **Mismatch de versão Frida (`frida.py`):** ao injetar o Gadget, avisa quando a
  versão do Frida CLI instalado difere da versão do Gadget (causa attach falhar) e
  mostra o `pip install` para alinhar.
- **Keystore relativa ao CWD (`state.py`):** o caminho padrão da keystore era
  `resources/key.jks` resolvido contra o diretório atual, então rodar a ferramenta
  de fora do repo dava `Keystore não encontrado`. Agora o padrão aponta para a
  keystore empacotada (caminho absoluto) e é encontrada de qualquer pasta.
- **Install incremental (`splits.py`, `device.py`):** `adb install`/`install-multiple`
  tentavam install-incremental e cuspiam um traceback Java em emuladores antes de cair
  no modo normal. Agora passamos `--no-incremental` — saída limpa (`Success`).
- **Opção 16 (beco sem saída):** `sign_split_set` exigia um base patcheado já
  assinado e, sem ele, abortava com `Assine o base patcheado primeiro`. Agora a
  opção 16 oferece (a) usar o base patcheado, (b) buildar+assinar na hora se há
  pasta descompilada, ou (c) re-assinar o base ORIGINAL — o caso comum de só
  querer instalar um conjunto base+splits de terceiros com a sua chave.

### Adicionado
- **Projeto persistente (`state.py`):** configuração (APK, keystore, senha, alias,
  versão do Frida, ABIs) é gravada em `dexstrike.json` na pasta do APK e recarregada
  automaticamente no próximo run a partir daquela pasta.
- **Download via adb (`pull.py`, opção 17):** lista pacotes de terceiros do device,
  resolve base + splits via `pm path` e baixa tudo (`adb pull`) para uma pasta de
  projeto, já configurando o state para assinar/instalar.
- **License Check (`license_check.py`):** detecção de proteções de licença/anti-tamper
  (PairIP License Check, PairIP VM Protection nativa e Google Play Licensing/LVL) e
  bypass automático do PairIP — neutraliza os métodos `start*Activity` de
  `LicenseClient` (paywall/erro) tornando-os no-op no smali, sem alterar a validação
  de assinatura do payload. Opções de menu 14 (detectar) e 15 (bypass).
- **Splits / `install-multiple` (`splits.py`):** descoberta de split APKs irmãos do
  base, verificação de que base + splits compartilham o mesmo certificado, assinatura
  do conjunto com a mesma keystore em `outputs/signed/` e instalação via
  `adb install-multiple`. Opção de menu 16.
- **Pipeline (10):** oferece o bypass de License Check quando detectado e a
  assinatura/instalação do conjunto de splits ao final.
- **smali.py:** `neuter_methods`/`neuter_void_method` para transformar métodos `void`
  em no-op de forma idempotente, respeitando blocos `.annotation`/`.param`.
- **signer.py:** helpers reutilizáveis `zipalign_file`, `sign_with_keystore`
  (alias explícito) e `cert_sha256`.
- Testes para `license_check` e `splits`.

## [0.1.0]

### Adicionado
- Menu interativo cobrindo todo o fluxo: decompile, patch de Manifest, detecção,
  injeção do Frida Gadget, patch de smali, rebuild, zipalign, assinatura e relatório.
- Pipeline completo recomendado (opção 10).
- Suíte de testes `pytest` (manifesto, smali e detecção).
- Integração contínua via GitHub Actions (Python 3.10–3.13).
- Gerador de imagens do projeto (`scripts/generate_assets.py`).

### Corrigido
- **Manifest:** preservação de todos os namespaces XML (`android`, `tools`, custom)
  antes do parse, evitando reescrita como `ns0:`/`ns1:` que quebrava o rebuild.
- **Detector:** o scan agora cobre todas as pastas `smali_classes*` (multidex), e não
  apenas `smali` e `smali_classes2`.
- **Frida:** download robusto com arquivo temporário `.part`, mensagens claras para
  HTTP 404 / falha de rede e remoção automática de `.xz` corrompido do cache.
- **utils:** `run_cmd` normaliza argumentos para string e converte `FileNotFoundError`
  em erro legível.
- **Relatório:** instrução de uso do Frida alinhada ao modo *listen* do Gadget.

### Empacotamento
- `pyproject.toml` com `build-system`, `package-data` (scripts Frida) e extra `dev`.
