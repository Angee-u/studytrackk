import os
from flask import Flask, request, jsonify
import bcrypt
from supabase import create_client, Client

app = Flask(__name__)

# Variáveis de ambiente configuradas no painel da Vercel
# (Project Settings > Environment Variables)
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def hash_senha(senha_plana: str) -> str:
    """Gera um hash bcrypt da senha. Nunca guardamos texto plano."""
    return bcrypt.hashpw(senha_plana.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


@app.after_request
def liberar_cors(response):
    # Equivalente ao middleware cors() do Express — libera o front (Flutter/app)
    # a chamar esses endpoints de outra origem.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/api/usuarios", methods=["GET"])
def listar_usuarios():
    """Lista usuários (sem expor o hash da senha)."""
    try:
        resp = (
            supabase.table("usuarios")
            .select("id, nome, email, criado_em, atualizado_em")
            .order("id")
            .execute()
        )
        return jsonify(usuarios=resp.data), 200
    except Exception as e:
        return jsonify(erro=str(e)), 500


@app.route("/api/usuarios", methods=["POST"])
def criar_usuario():
    """Cria um novo usuário (cadastro)."""
    dados = request.get_json(silent=True) or {}

    nome = (dados.get("nome") or "").strip()
    email = (dados.get("email") or "").strip().lower()
    senha = dados.get("senha") or ""

    if not nome or not email or not senha:
        return jsonify(erro="nome, email e senha são obrigatórios"), 400

    if len(senha) < 6:
        return jsonify(erro="senha deve ter pelo menos 6 caracteres"), 400

    senha_hash = hash_senha(senha)

    try:
        resp = (
            supabase.table("usuarios")
            .insert({"nome": nome, "email": email, "senha_hash": senha_hash})
            .execute()
        )
        usuario_criado = resp.data[0]
        usuario_criado.pop("senha_hash", None)  # nunca retornar o hash
        return jsonify(usuario=usuario_criado), 201

    except Exception as e:
        msg = str(e)
        # Supabase retorna erro de UNIQUE constraint quando o email já existe
        if "duplicate key" in msg or "usuarios_email_key" in msg:
            return jsonify(erro="e-mail já cadastrado"), 409
        return jsonify(erro=msg), 500