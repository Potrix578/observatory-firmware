# Observatório de firmware

Compara duas versões do OpenWrt para um router e mostra o que mudou: pacotes, serviços, endurecimento e vulnerabilidades em aberto. Nenhum código do firmware é executado.

## Preparar

Precisa de Python 3.14 ou mais recente, por causa do suporte nativo a zstd.

```bash
python -m venv .venv
```

```bash
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Correr

```bash
.venv\Scripts\python.exe -I tools/observatory.py tplink_archer-c7-v5 24.10.8 25.12.6
```

O relatório fica em `reports/<dispositivo>/<antiga>_to_<nova>.md`. Uma segunda execução só repete os passos com entradas alteradas. As fontes de CVE são renovadas ao fim de 7 dias.

O comando também atualiza o site em `site/`. O `index.html` é uma página única que funciona em qualquer alojamento estático, e pode ser reconstruída com:

```bash
.venv\Scripts\python.exe -I tools/build_site.py site
```

## Acrescentar um router

Junte o nome e o alvo do OpenWrt a `data/devices.json`. O alvo tem de ter `kernel-debug.tar.zst` e `kmod-ikconfig` publicados. Por agora, só são suportadas imagens `sysupgrade` de 32 bits com uImage e SquashFS.

## Revisão manual

Os vereditos ficam em `data/triage/<dispositivo>.json`, por versão:

- `components`: programas fora do kernel.
- `kernel`: CVEs do kernel.

Um veredito só vale para o dispositivo revisto, porque muitos dependem da compilação. O `data/fixed-by-hand.json` guarda confirmações no código por versão do kernel, e essas valem para qualquer router com esse kernel.

## Publicar

O site é publicado no GitHub Pages pelo ficheiro `.github/workflows/pages.yml`, sempre que `site/` muda no ramo `main`. Em Settings, Pages, escolha GitHub Actions como origem.

O site não faz pedidos a terceiros: as letras estão em `site/fonts`, com as respetivas licenças.

## Redistribuição

As imagens, os arquivos do kernel, as caches e os resultados intermédios ficam fora do Git. Publique apenas metadados, hashes e resultados.

## Dados

Este produto usa dados da API do NVD, mas não é aprovado nem certificado pelo NVD. Também usa dados do OSV e da Lista de CVE.

## Licença

O código está sob a licença MIT: ver `LICENSE`. As letras em `site/fonts` mantêm as suas próprias licenças, e os dados de terceiros seguem os termos das respetivas fontes.
