# Indica+ Final

Arquivos finais para publicação manual.

## Estrutura
- `worker.js` -> Cloudflare Worker/API
- `aluno.html` -> área pública do aluno
- `index.html` -> redireciona para `aluno.html`
- `admin/index.html` -> painel administrativo
- `js/config.js` -> configuração da API

## API
`https://indica-mais-api.evoluamaisprofissoes.workers.dev`

## Publicação
1. Substitua o Worker atual pelo `worker.js` e faça Deploy.
2. No GitHub Pages, substitua/adapte os arquivos do frontend.
3. Abra `/admin/` para o painel.
4. Abra `/aluno.html` para a área do aluno.

## Regra de negócio
Indicação não gera ticket. Ticket somente após matrícula paga, 7 dias de segurança e confirmação administrativa. O sorteio é validado no servidor.
