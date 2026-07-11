# host-ids

Sistema de detecção de intrusão baseado em host (**HIDS**) para Linux. Monitora
continuamente o sistema e emite **alertas** quando detecta mudanças suspeitas —
sem dependências externas (usa `/proc` e a stdlib).

> ⚠️ Ferramenta educacional/defensiva. Rode no **seu próprio** sistema. Alguma
> visibilidade (todos os processos/arquivos) exige privilégios.

## Instalação

Pré-requisitos: **Python 3.10+**.

```bash
git clone https://github.com/Diogo-Damasceno/host-ids.git
cd host-ids
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Após instalar, o comando do projeto fica disponível dentro do venv.
Para usar fora dele, crie um atalho:

```bash
mkdir -p ~/.local/bin
ln -sf "$(pwd)/.venv/bin/hostids" ~/.local/bin/hostids
```

> Dica: se `~/.local/bin` não estiver no teu `PATH`, rode
> `export PATH="$HOME/.local/bin:$PATH"` (e adicione ao `~/.bashrc`/`~/.zshrc`).


## Uso

```bash
# monitora continuamente (intervalo de 3s)
hostids

# cria o baseline uma vez e sai
hostids --once

# saida sem cores (log/pipe)
hostids --plain --interval 5
```

## Licença

MIT — veja `LICENSE`.
