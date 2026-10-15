# GHSA-g48h-h5pc-396j — Path traversal no LaraDashboard com exclusão/escrita arbitrária (RCE)

[English](README.md) · [Advisory oficial](https://github.com/laradashboard/laradashboard/security/advisories/GHSA-g48h-h5pc-396j)

Evidência pública e material seguro de reprodução local para uma vulnerabilidade de path traversal no gerenciamento de backups de atualização do LaraDashboard.

## Resumo técnico

| Campo | Valor |
|---|---|
| Produto | LaraDashboard |
| Versões afetadas | `>= 0.9.2, <= 1.2.2` |
| Revisão testada | `9dc1335835701651aef3adcb3e885acecb32402c` |
| CWE | CWE-22 |
| Severidade | Alta — CVSS 3.1 `7.2` |
| Permissão necessária | `settings.edit` (sem Superadmin) |
| Advisory | `GHSA-g48h-h5pc-396j` |

`CoreUpgradeController` e `BackupService` concatenam `backup_file`/`filename` ao diretório de backups sem normalizar o caminho ou confirmar que o arquivo resolvido permanece dentro de `storage/app/core-backups`.

Um usuário não Superadmin com a permissão delegável `settings.edit` consegue usar `../` para excluir arquivos fora do diretório de backups. O fluxo de restauração também aceita um ZIP escolhido pelo atacante que já esteja no disco e copia seu conteúdo para diretórios da aplicação, permitindo escrita arbitrária e possível execução remota de código.

## PoC

O diretório [`poc/`](poc/) contém um verificador estático não invasivo, uma PoC HTTP limitada a loopback para excluir um arquivo-canário e os formatos de requisição usados na validação original.

A PoC recusa alvos que não sejam loopback e exige `--execute`. Utilize apenas uma instalação descartável e um arquivo-canário criado especificamente para o teste.

## Correção recomendada

- aceitar somente nomes simples, sem componentes de diretório;
- resolver caminhos com `realpath()`;
- verificar contenção no diretório canônico de backups;
- centralizar essa verificação nos fluxos de exclusão, restauração e download;
- adicionar uma allowlist estrita de caracteres para o nome do backup.

## Divulgação

Reportado por [capivara-research](https://github.com/capivara-research) via GitHub Private Vulnerability Reporting e publicado pelo projeto em 30/08/2026.

## Aviso legal

Use somente em sistemas próprios ou com autorização explícita. O material destina-se a laboratórios locais e descartáveis.
