# studyTrack — Backend (Python + Flask + Vercel + Supabase)

CRUD inicial da entidade `usuarios`: cadastro (POST) e listagem (GET).

## Estrutura

```
studytrack-backend/
├── api/
│   └── index.py     # app Flask — entrypoint que a Vercel detecta
├── requirements.txt
└── README.md
```

A Vercel detecta o Flask automaticamente pela dependência no `requirements.txt`
e pelo arquivo `api/index.py` (que expõe uma variável de nível superior
chamada `app`). Não precisa de `vercel.json` nem de rotas manuais — o Flask
cuida do roteamento (`@app.route(...)`) e a Vercel manda toda requisição pra
esse app único.

## 1. Configurar o Supabase

1. No painel do Supabase, rode a criação da tabela `usuarios` (você já tem o schema).
2. Pegue a **Project URL** e a **anon/public key** (ou a **service_role key**, se quiser
   que o backend ignore RLS — nesse caso, guarde-a com cuidado, ela nunca deve ir
   para o front-end).
3. Se a tabela `usuarios` tiver RLS (Row Level Security) ativado, ou você libera
   policies para `insert`/`select`, ou usa a `service_role key` no backend (mais
   simples para essa primeira etapa).

## 2. Rodar localmente

```bash
cd studytrack-backend
npm i -g vercel        # se ainda não tiver a CLI da Vercel

python -m venv .venv
source .venv/bin/activate    # no Windows: .venv\Scripts\activate
pip install -r requirements.txt

vercel link             # conecta essa pasta a um projeto Vercel
vercel env pull         # baixa as env vars configuradas no painel para .env.local
```

Se preferir configurar na mão, crie um `.env.local`:
```
SUPABASE_URL=https://SEU-PROJETO.supabase.co
SUPABASE_KEY=sua-chave
```

Depois:
```bash
vercel dev
```

O endpoint sobe em algo como `http://localhost:3000/api/usuarios`. Use sempre
`vercel dev` (não o servidor embutido do Flask) — ele roda seu app do mesmo
jeito que a produção, com o mesmo entrypoint WSGI.

## 3. Testar

Criar usuário:
```bash
curl -X POST http://localhost:3000/api/usuarios \
  -H "Content-Type: application/json" \
  -d '{"nome": "Angelo", "email": "angelo@teste.com", "senha": "123456"}'
```

Listar usuários:
```bash
curl http://localhost:3000/api/usuarios
```

## 4. Deploy

```bash
vercel
```

Depois, no painel da Vercel, em **Settings > Environment Variables**, adicione:
- `SUPABASE_URL`
- `SUPABASE_KEY`

E faça o redeploy (`vercel --prod`).

## Próximos passos sugeridos

- Endpoint de login (`/api/login`): buscar por `email`, comparar com
  `bcrypt.checkpw`, retornar um JWT.
- Endpoint de recuperação de senha.
- CRUD de `materias`, `tarefas`, `exames` seguindo o mesmo padrão — cada um
  vira só mais algumas rotas `@app.route(...)` dentro do mesmo `api/index.py`,
  ou um blueprint separado se o arquivo crescer muito.
- Middleware simples de autenticação (validar JWT nas rotas protegidas, usando
  `@app.before_request` do Flask).
