# Indica+ Final

## Arquivos
- `worker-indica-mais-final.js`: Worker/API atualizado.
- `admin/index.html`: painel administrativo completo.
- `indica-mais-schema.sql`: schema completo atualizado.
- `database-migration.sql`: migração segura para banco já existente.

## Upload
1. Substitua o Worker pelo conteúdo de `worker-indica-mais-final.js` e faça o deploy.
2. Substitua `admin/index.html` no GitHub Pages.
3. Se o banco já existe e está funcionando, execute somente `database-migration.sql` no D1. Não apague tabelas nem recrie o banco.
4. Teste `/api/health`.
5. Entre no Admin.

## Novidades do Admin
- Criar, editar, ativar, pausar e arquivar campanhas.
- Campos de banner, logo e fundo por URL.
- CRUD de prêmios.
- Editar alunos.
- Editar/cancelar indicações.
- Confirmar matrícula quando os 7 dias forem cumpridos.
- Liberar ticket antecipadamente com motivo obrigatório e auditoria.
- Revogar ticket disponível.
- Ranking.
- Histórico de auditoria.
- Exportações CSV compatíveis com Excel.

## Regra de segurança
A regra oficial continua sendo 7 dias. A rota `confirm-early` é uma exceção administrativa deliberada e sempre registra o motivo no histórico.

## Importante
Campanhas, prêmios e tickets que já possuem histórico não são apagados fisicamente. Eles podem ser arquivados/desativados para preservar a integridade dos sorteios e da auditoria.
