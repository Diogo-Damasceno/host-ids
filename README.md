# Host IDS 🛡️

Sistema de detecção de intrusão baseado em host (**HIDS**) para Linux. Monitora continuamente o sistema e emite **alertas** quando detecta mudanças suspeitas — sem dependências externas (usa `/proc` e a stdlib).

> ⚠️ Ferramenta educacional/defensiva. Rode no **seu próprio** sistema. Alguns dados (todos os processos/arquivos) exigem privilégios para visibilidade completa.

## O que monitora

- **Novos processos** — com detecção de linhas de comando suspeitas (reverse shell `bash -i`, `/dev/tcp/`, `nc -e`, `curl | sh`, base64 decode, nmap…)
- **Novas conexões de rede** — TCP/UDP via `/proc/net`, destacando destinos externos
- **Usuários logados** — alerta em novas sessões interativas
- **Integridade de arquivos** — hash SHA256 de arquivos/diretórios monitorados (modificação/remoção/criação)

## Severidades

`info` (verde) · `warning` (amarelo) · `critical` (vermelho)

## Instalação

```bash
git clone https://github.com/Diogo-Damasceno/host-ids.git
cd host-ids
pip install -e .
```

## Uso

```bash
# monitorar processos/conexões/usuários a cada 3s
hostids

# incluir integridade de arquivos críticos
hostids -w /etc/passwd -w /etc/shadow -w ~/.ssh/authorized_keys

# intervalo customizado
hostids -i 1.5 -w /etc/crontab

# apenas baseline (uma varredura) e sair
hostids --once
```

### Testar a detecção

Em outro terminal, dispare algo suspeito (no seu próprio host):

```bash
bash -i >& /dev/tcp/127.0.0.1/9999 0>&1   # gera alerta critical
echo "x" >> /etc/... (num arquivo monitorado)  # gera alerta de integridade
```

## Testes

```bash
pip install -e '.[dev]'
pytest -q
```

## Arquitetura

```
hostids/
├── collectors.py  # snapshots via /proc (processos, conexões, usuários, hashes)
├── engine.py      # diff de snapshots + regras de alerta
└── cli.py         # loop de monitoramento
```

## Licença

MIT
