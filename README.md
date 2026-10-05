# Indica+

MVP do sistema de campanhas de indicação.

## O que já funciona nesta primeira versão

- Site público responsivo
- Área do aluno
- Cadastro de indicação
- Painel administrativo
- Controle de indicações
- Regra de 7 dias para elegibilidade
- Confirmação manual da matrícula
- Geração de ticket único após confirmação
- Cadastro e estoque de prêmios
- Sorteio usando ticket disponível
- Histórico básico de tickets e prêmios
- Personalização da campanha pelo admin
- Relatórios de leads e ranking
- Exportação CSV compatível com Excel
- Impressão de relatório em PDF pelo navegador
- PWA básico

## Importante

Esta versão usa `localStorage` apenas para permitir testes imediatos no navegador.

A próxima etapa de produção é substituir o armazenamento local pelo:

- Cloudflare Workers
- Cloudflare D1
- autenticação administrativa
- armazenamento de imagens
- regras de sorteio no backend

Nunca coloque segredos, tokens ou credenciais diretamente no frontend.

## Estrutura

- `/index.html` página pública
- `/aluno.html` área do aluno
- `/admin/index.html` painel administrativo
- `/css` estilos
- `/js` lógica
- `/assets` ícones e imagens
