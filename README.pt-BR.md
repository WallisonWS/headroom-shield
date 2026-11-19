<div align="center">

# ⚡ Headroom Shield — Compressor de Contexto LLM Sem Dependências + Escudo OWASP

[![Web Studio Ao Vivo](https://img.shields.io/badge/🌐_Abrir_Web_Studio-Testar_Online-0ea5e9?style=for-the-badge)](https://wallisonws.github.io/headroom-shield/)
[![Zero Dependências](https://img.shields.io/badge/Dependências-Zero_(Python_&_JS_&_Pwsh)-10b981?style=for-the-badge)](#)
[![Zero Telemetria](https://img.shields.io/badge/Telemetria-100%25_Desativada-6366f1?style=for-the-badge)](#)
[![Licença Apache 2.0](https://img.shields.io/badge/Licença-Apache_2.0-f59e0b?style=for-the-badge)](LICENSE)

<p align="center">
  <a href="README.md"><img src="https://img.shields.io/badge/🇺🇸_Read_in_English-Global-38bdf8?style=flat-square" /></a>
  <a href="README.pt-BR.md"><img src="https://img.shields.io/badge/🇧🇷_Português_(BR)-Ativo-1e293b?style=flat-square" /></a>
  <a href="docs/ARCHITECTURE.md"><img src="https://img.shields.io/badge/📐_Arquitetura_&_Auditoria_REA-Ver_Docs-a855f7?style=flat-square" /></a>
</p>

**Comprima saídas de ferramentas, arrays JSON, logs de servidores, diffs e chunks RAG em 60–95% ANTES de chegarem ao Gemini, Claude ou ChatGPT — com Escudo OWASP LLM contra Prompt Injection, Cofre Reversível LGPD/PII, Servidor MCP sem dependências, Proxy Local e Estúdio Web interativo.**

</div>

---

## 🔥 Principais Melhorias em Relação ao Headroom OSS Original

Após engenharia reversa estática e inspeção SQLite com **REA (Reverse Engineer Anything)** sobre o [`headroomlabs-ai/headroom`](https://github.com/headroomlabs-ai/headroom), criamos o **Headroom Shield** resolvendo os maiores gargalos do projeto original:

1. **🛡️ Escudo de Segurança Estágio-0 Open-Source:** O Headroom original deixa a proteção de tokens (*"tokens secured"*) restrita ao plano Enterprise pago. O **Headroom Shield** neutraliza **Indirect Prompt Injections (`OWASP LLM01/06/07`)**, remove caracteres invisíveis **Unicode/BiDi**, bloqueia exfiltração via imagem Markdown e anonimiza **CPF, CNPJ, E-mail, IPs internos e chaves AWS/Google** em um cofre reversível **gratuitamente**.
2. **📦 Zero Dependências Externas (Portátil de Verdade):** O Headroom original exige extensão compilada em Rust (`headroom._core` via PyO3) sem fallback Python, além de `mcp` e `httpx`. O **Headroom Shield** roda nativamente com **biblioteca padrão do Python 3**, **JS/TS ESM**, **Windows PowerShell** e **100% no Navegador**.
3. **🔇 100% Zero Telemetria por Padrão:** Diferente do beacon de telemetria ligado por padrão no upstream, o Headroom Shield não envia nenhum dado para servidores externos.
4. **🗄️ Banco CCR SQLite Otimizado com Compressão `zlib`:** Compatível com o esquema SQLite WAL observado pelo REA (`ccr_entries` + índice de expiração TTL), agora comprimindo o conteúdo em disco com `zlib`.
5. **🌐 Web Studio Interativo Trilíngue (`PT-BR / EN / ES`):** Teste ao vivo em https://wallisonws.github.io/headroom-shield/!

---

## 🚀 Como Usar

* **Biblioteca Python:** `from headroom_shield import compress_content, CCRStore`
* **Servidor MCP (Antigravity, Claude Code, Cursor, Codex):** `python3 -m headroom_shield.mcp_server`
* **Proxy Local HTTP (OpenAI / Anthropic / Gemini):** `python3 -m headroom_shield.proxy_server --port 8787`
* **PowerShell Nativo (Windows):** `.\headroom_shield.ps1 -FilePath .\server.log`

Consulte o guia completo em [docs/MCP_AND_PROXY_GUIDE.md](docs/MCP_AND_PROXY_GUIDE.md) e a arquitetura técnica em [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
