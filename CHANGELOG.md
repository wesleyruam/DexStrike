# Changelog

Formato baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/).

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
