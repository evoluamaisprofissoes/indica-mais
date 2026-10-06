# Checklist de publicação do Indica+

## 1. D1
Se a tabela `student_sessions` ainda não existir, execute `database.sql` no D1 `indica-mais-db`.

Se as tabelas principais já existem, o arquivo usa `CREATE TABLE IF NOT EXISTS`, então não apaga dados.

## 2. Worker
Substitua o código do Worker atual pelo `worker.js` e publique em:
`indica-mais-api.evoluamaisprofissoes.workers.dev`

Binding:
- variável: `DB`
- D1: `indica-mais-db`

## 3. GitHub Pages
Suba:
- `aluno.html`
- `index.html`
- `admin/index.html`
- `js/config.js`

## 4. URLs
Aluno:
`https://evoluamaisprofissoes.github.io/indica-mais/aluno.html`

Admin:
`https://evoluamaisprofissoes.github.io/indica-mais/admin/`

## 5. Primeiro acesso administrativo
E-mail:
`evoluamaisprofissoes@gmail.com`

Na primeira entrada, o Worker inicializa a senha informada. Depois disso a senha fica armazenada como hash PBKDF2 no D1.

## 6. Teste mínimo
1. GET `/api/health` deve retornar API e database online.
2. Entrar no admin.
3. Cadastrar um prêmio.
4. Criar/usar um aluno.
5. Fazer uma indicação.
6. Registrar a matrícula no fluxo administrativo existente.
7. Testar o bloqueio antes dos 7 dias.
8. Depois do prazo, confirmar e verificar geração do ticket.
9. Realizar sorteio.
10. Conferir estoque, ticket usado e histórico.
11. Tentar usar o mesmo ticket novamente. Deve ser bloqueado.
