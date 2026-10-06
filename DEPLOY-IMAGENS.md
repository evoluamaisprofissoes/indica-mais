# Indica+ | Upload de imagens dos prêmios

## 1. Cloudflare R2
No Cloudflare, crie um bucket R2, por exemplo:
`indica-mais-imagens`

Depois abra o Worker `indica-mais-api` > Settings > Bindings > Add binding > R2 bucket.

Use exatamente:
- Variable name: `IMAGES`
- R2 bucket: `indica-mais-imagens`

Salve a configuração.

## 2. Worker
Substitua o código do Worker pelo `worker-indica-mais-final.js` e faça Deploy.

## 3. GitHub
Substitua:
`admin/index.html`

pelo arquivo deste pacote.

## 4. D1
Se ainda não existir, execute `database-migration.sql` no D1. Ele só cria a tabela de sessões de aluno caso necessário e não apaga dados.

## 5. Funcionamento
No cadastro/edição de prêmio, o Admin agora permite selecionar JPG, PNG ou WEBP de até 5 MB. A imagem é enviada para R2 pelo Worker e o D1 guarda apenas a URL pública `/media/...`.
