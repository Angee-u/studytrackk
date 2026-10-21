import os
import json
from datetime import datetime, timedelta, timezone, time
from zoneinfo import ZoneInfo
import hashlib
import hmac
import secrets
import re
from functools import wraps
from flask import Flask, request, jsonify, g
import bcrypt
import jwt
from supabase import create_client, Client

app = Flask(__name__)

# As credenciais ficam na Vercel, não no código nem no aplicativo.
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Defina SUPABASE_URL e SUPABASE_KEY nas variáveis de ambiente")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

JWT_SECRET = os.environ.get("JWT_SECRET", "")
if len(JWT_SECRET.encode("utf-8")) < 32:
    raise RuntimeError("Defina JWT_SECRET com pelo menos 32 bytes aleatórios")
JWT_ISSUER = "studytrack-api"
JWT_AUDIENCE = "studytrack-mobile"
JWT_TEMPO_MINUTOS = 60


def _resumo_senha(senha_hash):
    # Vincula o token à senha atual: trocar a senha encerra as sessões anteriores.
    return hmac.new(JWT_SECRET.encode("utf-8"), senha_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def _usuario_seguro(usuario):
    return {chave: valor for chave, valor in usuario.items() if chave != "senha_hash"}


def _criar_token(usuario):
    instante = datetime.now(timezone.utc)
    claims = {
        "sub": str(usuario["id"]), "iss": JWT_ISSUER, "aud": JWT_AUDIENCE,
        "iat": instante, "nbf": instante,
        "exp": instante + timedelta(minutes=JWT_TEMPO_MINUTOS),
        "jti": secrets.token_urlsafe(24),
        "pwd": _resumo_senha(usuario["senha_hash"]),
    }
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")


@app.before_request
def autenticar_requisicao():
    if request.method == "OPTIONS" or request.path == "/":
        return None
    if (request.path == "/api/usuarios" and request.method == "POST") or (
        request.path in ("/api/auth/login", "/api/auth/recuperar-senha", "/api/auth/redefinir-senha")
        and request.method == "POST"
    ) or (request.path == "/api/interno/processar-lembretes" and request.method == "POST"):
        return None

    cabecalho = request.headers.get("Authorization", "")
    partes = cabecalho.split()
    if len(partes) != 2 or partes[0].lower() != "bearer":
        return jsonify(erro="envie Authorization: Bearer <token>"), 401

    try:
        claims = jwt.decode(
            partes[1], JWT_SECRET, algorithms=["HS256"],
            issuer=JWT_ISSUER, audience=JWT_AUDIENCE,
            options={"require": ["sub", "iss", "aud", "iat", "nbf", "exp", "jti", "pwd"]},
            leeway=0,
        )
        usuario_id = int(claims["sub"])
        if usuario_id <= 0:
            raise ValueError("ID inválido")
    except (jwt.InvalidTokenError, ValueError, TypeError):
        return jsonify(erro="token inválido ou expirado"), 401

    try:
        usuarios = (supabase.table("usuarios")
                    .select("id, nome, email, senha_hash, criado_em, atualizado_em")
                    .eq("id", usuario_id).execute().data)
        if not usuarios or not usuarios[0].get("senha_hash"):
            return jsonify(erro="usuário não encontrado ou desativado"), 401
        usuario = usuarios[0]
        if not hmac.compare_digest(claims["pwd"], _resumo_senha(usuario["senha_hash"])):
            return jsonify(erro="sessão encerrada, faça login novamente"), 401
        revogados = (supabase.table("tokens_revogados").select("jti")
                     .eq("jti", claims["jti"]).execute().data)
        if revogados:
            return jsonify(erro="sessão encerrada, faça login novamente"), 401
        g.usuario_id = usuario_id
        g.usuario = usuario
        g.jwt_claims = claims
    except Exception:
        app.logger.exception("Falha ao validar sessão JWT")
        return jsonify(erro="não foi possível validar a sessão"), 503
    return None


def _usuario_logado():
    return g.usuario_id


def _validar_usuario_informado(valor):
    # Quem identifica o estudante é o JWT, não o ID enviado pelo aplicativo.
    if valor is None:
        return None
    try:
        if int(valor) != _usuario_logado():
            return jsonify(erro="não é permitido acessar dados de outro usuário"), 403
    except (ValueError, TypeError):
        return jsonify(erro="usuario_id inválido"), 400
    return None


def _pertence_ao_usuario(tabela, registro_id):
    if tabela == "materias":
        resposta = (supabase.table("materias").select("id, usuario_id")
                    .eq("id", registro_id).eq("usuario_id", _usuario_logado()).execute())
    elif tabela in ("tarefas", "exames"):
        resposta = (supabase.table(tabela)
                    .select("id, materia_id, materias!inner(usuario_id)")
                    .eq("id", registro_id).eq("materias.usuario_id", _usuario_logado()).execute())
    elif tabela == "horarios_aula":
        resposta = (supabase.table("horarios_aula")
                    .select("id, materia_id, materias!inner(usuario_id)")
                    .eq("id", registro_id).eq("materias.usuario_id", _usuario_logado()).execute())
    else:
        return False
    return bool(resposta.data)


def _exigir_propriedade(tabela, registro_id):
    try:
        if not _pertence_ao_usuario(tabela, registro_id):
            return jsonify(erro="registro não encontrado"), 404
    except Exception:
        app.logger.exception("Erro ao consultar proprietário do registro")
        return jsonify(erro="não foi possível verificar o registro"), 503
    return None


@app.route("/api/auth/login", methods=["POST"])
def login():
    dados = request.get_json(silent=True) or {}
    email_bruto = dados.get("email")
    email = email_bruto.strip().lower() if isinstance(email_bruto, str) else ""
    senha = dados.get("senha")
    if not email or not isinstance(senha, str) or not senha:
        return jsonify(erro="email e senha são obrigatórios"), 400
    try:
        usuarios = (supabase.table("usuarios")
                    .select("id, nome, email, senha_hash, criado_em, atualizado_em")
                    .eq("email", email).execute().data)
        usuario = usuarios[0] if usuarios else None
        # Verificamos um hash fictício para e-mails desconhecidos, reduzindo diferenças de tempo na resposta.
        hash_armazenado = usuario.get("senha_hash") if usuario else None
        hash_verificado = hash_armazenado or "$2b$12$C6UzMDM.H6dfI/f/IKcEeO6WaN0AkYQvG3bF6cCFNE9Y.l2nY0fZS"
        valido = bcrypt.checkpw(senha.encode("utf-8"), hash_verificado.encode("utf-8"))
        if not usuario or not valido:
            return jsonify(erro="email ou senha inválidos"), 401
        return jsonify(token=_criar_token(usuario), tipo="Bearer",
                       expira_em_segundos=JWT_TEMPO_MINUTOS * 60,
                       usuario=_usuario_seguro(usuario)), 200
    except (ValueError, TypeError):
        return jsonify(erro="email ou senha inválidos"), 401
    except Exception:
        app.logger.exception("Falha durante o login")
        return jsonify(erro="não foi possível realizar o login"), 503


@app.route("/api/auth/me", methods=["GET"])
def meu_perfil():
    return jsonify(usuario=_usuario_seguro(g.usuario)), 200


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    # Guardamos o identificador do token para que ele pare de valer antes de expirar.
    claims = g.jwt_claims
    try:
        supabase.table("tokens_revogados").insert({
            "jti": claims["jti"], "usuario_id": _usuario_logado(),
            "expira_em": datetime.fromtimestamp(claims["exp"], timezone.utc).isoformat(),
        }).execute()
        return jsonify(mensagem="sessão encerrada"), 200
    except Exception:
        app.logger.exception("Falha ao encerrar sessão")
        return jsonify(erro="não foi possível encerrar a sessão"), 503



@app.route("/", methods=["GET"])
def inicio():
    """Mostra que a API está respondendo quando alguém acessa a raiz."""
    return jsonify({
        "projeto": "studyTrack",
        "status": "online",
        "mensagem": "Backend disponível. A interface completa do app não está neste repositório."
    }), 200


def hash_senha(senha_plana: str) -> str:
    """Gera o hash bcrypt que será salvo no lugar da senha."""
    return bcrypt.hashpw(senha_plana.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def agora():
    """Retorna o horário UTC sem fuso para os campos atualizado_em."""
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def agora_brasil():
    """Usa o horário de Brasília para comparar datas salvas sem fuso horário."""
    return datetime.now(timezone(timedelta(hours=-3))).replace(tzinfo=None).isoformat()


def agora_do_usuario():
    """Usa o fuso do estudante ao consultar prazos; São Paulo é o padrão inicial."""
    fuso = "America/Sao_Paulo"
    try:
        preferencias = (supabase.table("preferencias_notificacao")
                        .select("fuso_horario").eq("usuario_id", _usuario_logado())
                        .execute().data)
        if preferencias and preferencias[0].get("fuso_horario"):
            fuso = preferencias[0]["fuso_horario"]
        return datetime.now(ZoneInfo(fuso)).replace(tzinfo=None).isoformat()
    except Exception:
        app.logger.exception("Não foi possível consultar o fuso horário")
        return agora_brasil()


def erro_banco(e):
    """Devolve mensagens mais úteis para erros conhecidos do banco."""
    msg = str(e)
    if "23503" in msg or "foreign key" in msg.lower():
        return jsonify(erro="referência inválida: o id informado (usuário/matéria) não existe"), 400
    if "invalid input value for enum" in msg:
        return jsonify(erro="valor inválido para um campo de opções (ex.: status)"), 400
    app.logger.exception("Erro inesperado no banco")
    return jsonify(erro="erro interno ao acessar o banco"), 500


def validar_horario_iso(dados, obrigatorio=False):
    """Confere os horários e os dias conforme o padrão ISO (segunda=1, domingo=7)."""
    if not isinstance(dados, dict):
        raise ValueError("o horário deve ser um objeto")
    campos = ("dia_semana", "hora_inicio", "hora_fim")
    if obrigatorio and any(c not in dados for c in campos):
        raise ValueError("dia_semana, hora_inicio e hora_fim são obrigatórios")
    if "dia_semana" in dados:
        dia = dados["dia_semana"]
        if type(dia) is not int or not 1 <= dia <= 7:
            raise ValueError("dia_semana deve estar entre 1 (segunda) e 7 (domingo)")
    horarios = {}
    for campo in ("hora_inicio", "hora_fim"):
        if campo in dados:
            valor = dados[campo]
            if not isinstance(valor, str) or not re.fullmatch(r"[0-2][0-9]:[0-5][0-9](?::[0-5][0-9])?", valor):
                raise ValueError(f"{campo} deve ser uma hora válida (HH:MM)")
            try:
                horario = time.fromisoformat(valor)
                if horario.tzinfo is not None:
                    raise ValueError()
            except ValueError:
                raise ValueError(f"{campo} deve ser uma hora válida (HH:MM)") from None
            horarios[campo] = horario
    if "hora_inicio" in horarios and "hora_fim" in horarios:
        if horarios["hora_fim"] <= horarios["hora_inicio"]:
            raise ValueError("hora_fim deve ser posterior a hora_inicio")


def atualizar(tabela, registro_id, dados, permitidos, chave, com_timestamp=True):
    """Atualiza somente os campos recebidos, após conferir o dono do registro."""
    negado = _exigir_propriedade(tabela, registro_id)
    if negado:
        return negado
    if tabela == "horarios_aula":
        try:
            atual = (supabase.table("horarios_aula")
                     .select("dia_semana,hora_inicio,hora_fim")
                     .eq("id", registro_id).execute().data)
            if not atual:
                return jsonify(erro="horário não encontrado"), 404
            validar_horario_iso({**atual[0], **dados}, obrigatorio=True)
        except ValueError as e:
            return jsonify(erro=str(e)), 400
        except Exception as e:
            return erro_banco(e)
    if tabela in ("tarefas", "exames") and "materia_id" in dados:
        negado = _exigir_propriedade("materias", dados["materia_id"])
        if negado:
            return negado
    campos = {c: dados[c] for c in permitidos if c in dados}
    if not campos:
        return jsonify(erro="envie ao menos um campo: " + ", ".join(permitidos)), 400
    if com_timestamp:
        campos["atualizado_em"] = agora()
    try:
        resp = supabase.table(tabela).update(campos).eq("id", registro_id).execute()
        if not resp.data:
            return jsonify(erro="registro não encontrado"), 404
        return jsonify({chave: resp.data[0]}), 200
    except Exception as e:
        return erro_banco(e)


def apagar(tabela, registro_id):
    """Exclui um registro somente depois de conferir a quem pertence."""
    negado = _exigir_propriedade(tabela, registro_id)
    if negado:
        return negado
    try:
        resp = supabase.table(tabela).delete().eq("id", registro_id).execute()
        if not resp.data:
            return jsonify(erro="registro não encontrado"), 404
        return jsonify(mensagem="apagado com sucesso"), 200
    except Exception as e:
        return erro_banco(e)


@app.after_request
def liberar_cors(response):
    # Libera chamadas do front web em outra origem. Flutter nativo não depende de CORS.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


@app.route("/api/usuarios", methods=["GET"])
def listar_usuarios():
    """Mostra apenas os dados da conta autenticada, sem a senha_hash."""
    try:
        resp = (
            supabase.table("usuarios")
            .select("id, nome, email, criado_em, atualizado_em")
            .eq("id", _usuario_logado())
            .order("id")
            .execute()
        )
        return jsonify(usuarios=resp.data), 200
    except Exception as e:
        app.logger.exception("Falha ao listar usuários")
        return jsonify(erro="não foi possível listar os usuários"), 500


@app.route("/api/usuarios", methods=["POST"])
def criar_usuario():
    """Cadastra uma conta de estudante."""
    dados = request.get_json(silent=True) or {}

    nome = dados.get("nome")
    email = dados.get("email")
    senha = dados.get("senha")
    if not isinstance(nome, str) or not isinstance(email, str) or not isinstance(senha, str):
        return jsonify(erro="nome, email e senha devem ser textos"), 400
    nome = nome.strip()
    email = email.strip().lower()

    if not nome or not email or not senha:
        return jsonify(erro="nome, email e senha são obrigatórios"), 400

    if len(senha) < 8 or len(senha.encode("utf-8")) > 72:
        return jsonify(erro="senha precisa ter 8 caracteres e no máximo 72 bytes"), 400

    senha_hash = hash_senha(senha)

    try:
        resp = (
            supabase.table("usuarios")
            .insert({"nome": nome, "email": email, "senha_hash": senha_hash})
            .execute()
        )
        usuario_criado = resp.data[0]
        usuario_criado.pop("senha_hash", None)  # O hash da senha não deve sair na resposta.
        return jsonify(usuario=usuario_criado), 201

    except Exception as e:
        msg = str(e)
        # O Supabase sinaliza e-mail repetido como erro de unicidade.
        if "duplicate key" in msg or "usuarios_email_key" in msg:
            return jsonify(erro="e-mail já cadastrado"), 409
        app.logger.exception("Falha ao cadastrar usuário")
        return jsonify(erro="erro interno ao cadastrar usuário"), 500


@app.route("/api/usuarios/<int:usuario_id>", methods=["PUT"])
def editar_usuario(usuario_id):
    """Altera somente os dados enviados para a conta atual."""
    dados = request.get_json(silent=True) or {}

    if usuario_id != _usuario_logado():
        return jsonify(erro="não é permitido editar outro usuário"), 403
    # A senha atual é necessária para alterar dados sensíveis.
    campos_para_atualizar = {}
    if "email" in dados or "senha" in dados:
        atual = dados.get("senha_atual") or ""
        if not isinstance(atual, str) or not bcrypt.checkpw(
            atual.encode("utf-8"), g.usuario["senha_hash"].encode("utf-8")
        ):
            return jsonify(erro="senha_atual inválida"), 403

    if "nome" in dados:
        nome = dados.get("nome")
        nome = nome.strip() if isinstance(nome, str) else ""
        if not nome:
            return jsonify(erro="nome não pode ser vazio"), 400
        campos_para_atualizar["nome"] = nome

    if "email" in dados:
        email = dados.get("email")
        email = email.strip().lower() if isinstance(email, str) else ""
        if not email:
            return jsonify(erro="email não pode ser vazio"), 400
        campos_para_atualizar["email"] = email

    if "senha" in dados:
        senha = dados.get("senha")
        if not isinstance(senha, str) or len(senha) < 8 or len(senha.encode("utf-8")) > 72:
            return jsonify(erro="senha precisa ter 8 caracteres e no máximo 72 bytes"), 400
        campos_para_atualizar["senha_hash"] = hash_senha(senha)

    if not campos_para_atualizar:
        return jsonify(erro="envie ao menos um campo para atualizar (nome, email ou senha)"), 400

    campos_para_atualizar["atualizado_em"] = agora()

    try:
        resp = (
            supabase.table("usuarios")
            .update(campos_para_atualizar)
            .eq("id", usuario_id)
            .execute()
        )

        if not resp.data:
            return jsonify(erro="usuário não encontrado"), 404

        usuario_atualizado = resp.data[0]
        usuario_atualizado.pop("senha_hash", None)
        return jsonify(usuario=usuario_atualizado), 200

    except Exception as e:
        msg = str(e)
        if "duplicate key" in msg or "usuarios_email_key" in msg:
            return jsonify(erro="e-mail já cadastrado"), 409
        app.logger.exception("Falha ao atualizar usuário")
        return jsonify(erro="erro interno ao atualizar usuário"), 500


@app.route("/api/usuarios/<int:usuario_id>", methods=["DELETE"])
def apagar_usuario(usuario_id):
    if usuario_id != _usuario_logado():
        return jsonify(erro="não é permitido apagar outro usuário"), 403
    # Confirma a senha antes de excluir a conta.
    dados = request.get_json(silent=True) or {}
    senha = dados.get("senha_atual") or ""
    if not isinstance(senha, str) or not bcrypt.checkpw(
        senha.encode("utf-8"), g.usuario["senha_hash"].encode("utf-8")
    ):
        return jsonify(erro="senha_atual inválida"), 403
    # O banco remove os dados relacionados de uma vez, sem exclusão pela metade.
    try:
        excluiu = supabase.rpc("excluir_conta_studytrack", {"p_usuario_id": usuario_id}).execute().data
        return (jsonify(mensagem="conta excluída"), 200) if excluiu is True else (jsonify(erro="usuário não encontrado"), 404)
    except Exception as e:
        return erro_banco(e)


# Matérias e horários de aula
@app.route("/api/materias", methods=["GET"])
def listar_materias():
    """Traz as matérias do estudante junto com os horários de aula."""
    usuario_id = request.args.get("usuario_id", type=int)
    negado = _validar_usuario_informado(usuario_id)
    if negado:
        return negado
    usuario_id = _usuario_logado()
    try:
        resp = (
            supabase.table("materias")
            .select("*, horarios_aula(*)")
            .eq("usuario_id", usuario_id)
            .order("nome")
            .execute()
        )
        return jsonify(materias=resp.data), 200
    except Exception as e:
        return erro_banco(e)


@app.route("/api/materias", methods=["POST"])
def criar_materia():
    """Cria uma matéria e, se vierem na requisição, seus horários de aula."""
    dados = request.get_json(silent=True) or {}
    usuario_id = dados.get("usuario_id")
    nome = (dados.get("nome") or "").strip()
    cor = (dados.get("cor") or "").strip()

    negado = _validar_usuario_informado(usuario_id)
    if negado:
        return negado
    usuario_id = _usuario_logado()
    if not nome or not cor:
        return jsonify(erro="nome e cor são obrigatórios"), 400

    horarios = dados.get("horarios", [])
    if horarios is None:
        horarios = []
    if not isinstance(horarios, list):
        return jsonify(erro="horarios deve ser uma lista"), 400
    try:
        for h in horarios:
            validar_horario_iso(h, obrigatorio=True)
    except ValueError as e:
        return jsonify(erro=str(e)), 400

    materia = None
    try:
        resp = (
            supabase.table("materias")
            .insert({
                "usuario_id": usuario_id,
                "nome": nome,
                "professor": dados.get("professor"),
                "cor": cor,
            })
            .execute()
        )
        materia = resp.data[0]

        if horarios:
            linhas = [
                {
                    "materia_id": materia["id"],
                    "dia_semana": h["dia_semana"],
                    "hora_inicio": h["hora_inicio"],
                    "hora_fim": h["hora_fim"],
                }
                for h in horarios
            ]
            materia["horarios_aula"] = supabase.table("horarios_aula").insert(linhas).execute().data

        return jsonify(materia=materia), 201
    except Exception as e:
        if materia:  # Desfaz o cadastro se algum horário não puder ser salvo.
            supabase.table("materias").delete().eq("id", materia["id"]).execute()
        return erro_banco(e)


@app.route("/api/materias/<int:materia_id>", methods=["PUT"])
def editar_materia(materia_id):
    dados = request.get_json(silent=True) or {}
    return atualizar("materias", materia_id, dados, ["nome", "professor", "cor"], "materia")


@app.route("/api/materias/<int:materia_id>", methods=["DELETE"])
def apagar_materia(materia_id):
    """Remove a matéria e seus horários, tarefas e exames."""
    negado = _exigir_propriedade("materias", materia_id)
    if negado:
        return negado
    try:
        for tabela in ("horarios_aula", "tarefas", "exames"):
            supabase.table(tabela).delete().eq("materia_id", materia_id).execute()
    except Exception as e:
        return erro_banco(e)
    return apagar("materias", materia_id)


@app.route("/api/materias/<int:materia_id>/horarios", methods=["POST"])
def criar_horario(materia_id):
    negado = _exigir_propriedade("materias", materia_id)
    if negado:
        return negado
    dados = request.get_json(silent=True) or {}
    try:
        validar_horario_iso(dados, obrigatorio=True)
    except ValueError as e:
        return jsonify(erro=str(e)), 400
    try:
        resp = (
            supabase.table("horarios_aula")
            .insert({
                "materia_id": materia_id,
                "dia_semana": dados["dia_semana"],
                "hora_inicio": dados["hora_inicio"],
                "hora_fim": dados["hora_fim"],
            })
            .execute()
        )
        return jsonify(horario=resp.data[0]), 201
    except Exception as e:
        return erro_banco(e)


@app.route("/api/horarios/<int:horario_id>", methods=["PUT"])
def editar_horario(horario_id):
    dados = request.get_json(silent=True) or {}
    return atualizar(
        "horarios_aula", horario_id, dados,
        ["dia_semana", "hora_inicio", "hora_fim"], "horario", com_timestamp=False,
    )


@app.route("/api/horarios/<int:horario_id>", methods=["DELETE"])
def apagar_horario(horario_id):
    return apagar("horarios_aula", horario_id)


# Tarefas
@app.route("/api/tarefas", methods=["GET"])
def listar_tarefas():
    """Lista as tarefas, com filtros opcionais de matéria, status e atraso."""
    usuario_id = request.args.get("usuario_id", type=int)
    negado = _validar_usuario_informado(usuario_id)
    if negado:
        return negado
    usuario_id = _usuario_logado()

    try:
        # A junção com matérias garante que só apareçam tarefas do estudante.
        q = (
            supabase.table("tarefas")
            .select("*, materias!inner(usuario_id, nome, cor)")
            .eq("materias.usuario_id", usuario_id)
        )

        materia_id = request.args.get("materia_id", type=int)
        if materia_id:
            q = q.eq("materia_id", materia_id)

        status = request.args.get("status")
        if status:
            q = q.eq("status", status)

        if request.args.get("vencidas") == "true":
            q = q.eq("status", "pendente").lt("data_entrega", agora_do_usuario())

        resp = q.order("data_entrega").execute()
        return jsonify(tarefas=resp.data), 200
    except Exception as e:
        return erro_banco(e)


@app.route("/api/tarefas", methods=["POST"])
def criar_tarefa():
    dados = request.get_json(silent=True) or {}
    materia_id = dados.get("materia_id")
    titulo = (dados.get("titulo") or "").strip()
    data_entrega = dados.get("data_entrega")

    if not materia_id or not titulo or not data_entrega:
        return jsonify(erro="materia_id, titulo e data_entrega são obrigatórios"), 400
    negado = _exigir_propriedade("materias", materia_id)
    if negado:
        return negado

    novo = {"materia_id": materia_id, "titulo": titulo, "data_entrega": data_entrega}
    if dados.get("descricao") is not None:
        novo["descricao"] = dados["descricao"]
    if dados.get("status"):
        novo["status"] = dados["status"]  # Sem status informado, o banco usa "pendente".

    try:
        resp = supabase.table("tarefas").insert(novo).execute()
        return jsonify(tarefa=resp.data[0]), 201
    except Exception as e:
        return erro_banco(e)


@app.route("/api/tarefas/<int:tarefa_id>", methods=["PUT"])
def editar_tarefa(tarefa_id):
    """Também permite marcar a tarefa como concluída pelo campo status."""
    dados = request.get_json(silent=True) or {}
    return atualizar(
        "tarefas", tarefa_id, dados,
        ["materia_id", "titulo", "descricao", "data_entrega", "status"], "tarefa",
    )


@app.route("/api/tarefas/<int:tarefa_id>", methods=["DELETE"])
def apagar_tarefa(tarefa_id):
    return apagar("tarefas", tarefa_id)


# Exames
@app.route("/api/exames", methods=["GET"])
def listar_exames():
    """Lista provas e permite filtrar por matéria ou mostrar só as futuras."""
    usuario_id = request.args.get("usuario_id", type=int)
    negado = _validar_usuario_informado(usuario_id)
    if negado:
        return negado
    usuario_id = _usuario_logado()

    try:
        q = (
            supabase.table("exames")
            .select("*, materias!inner(usuario_id, nome, cor)")
            .eq("materias.usuario_id", usuario_id)
        )

        materia_id = request.args.get("materia_id", type=int)
        if materia_id:
            q = q.eq("materia_id", materia_id)

        if request.args.get("proximos") == "true":
            q = q.gte("data_hora", agora_do_usuario())

        resp = q.order("data_hora").execute()
        return jsonify(exames=resp.data), 200
    except Exception as e:
        return erro_banco(e)


@app.route("/api/exames", methods=["POST"])
def criar_exame():
    dados = request.get_json(silent=True) or {}
    materia_id = dados.get("materia_id")
    data_hora = dados.get("data_hora")

    if not materia_id or not data_hora:
        return jsonify(erro="materia_id e data_hora são obrigatórios"), 400
    negado = _exigir_propriedade("materias", materia_id)
    if negado:
        return negado

    try:
        resp = (
            supabase.table("exames")
            .insert({
                "materia_id": materia_id,
                "data_hora": data_hora,
                "descricao": dados.get("descricao"),
            })
            .execute()
        )
        return jsonify(exame=resp.data[0]), 201
    except Exception as e:
        return erro_banco(e)


@app.route("/api/exames/<int:exame_id>", methods=["PUT"])
def editar_exame(exame_id):
    dados = request.get_json(silent=True) or {}
    return atualizar("exames", exame_id, dados, ["materia_id", "descricao", "data_hora"], "exame")


@app.route("/api/exames/<int:exame_id>", methods=["DELETE"])
def apagar_exame(exame_id):
    return apagar("exames", exame_id)


# Notificações push pelo Firebase. FIREBASE_CREDENTIALS deve conter o JSON
# da conta de serviço, configurado apenas no ambiente do servidor.
FCM_SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
_fcm_creds = None


def _credenciais_fcm():
    """Reutiliza as credenciais do Firebase e renova o acesso quando necessário."""
    global _fcm_creds
    if _fcm_creds is None:
        from google.oauth2 import service_account

        bruto = os.environ.get("FIREBASE_CREDENTIALS")
        if not bruto:
            raise RuntimeError("variável FIREBASE_CREDENTIALS não configurada")
        info = json.loads(bruto)
        _fcm_creds = service_account.Credentials.from_service_account_info(info, scopes=FCM_SCOPES)

    if not _fcm_creds.valid:
        from google.auth.transport.requests import Request as GoogleRequest

        _fcm_creds.refresh(GoogleRequest())
    return _fcm_creds


def enviar_push(fcm_token, titulo, corpo, dados=None):
    """Envia o push para um dispositivo e informa se deu certo."""
    import requests

    creds = _credenciais_fcm()
    url = f"https://fcm.googleapis.com/v1/projects/{creds.project_id}/messages:send"
    mensagem = {"token": fcm_token, "notification": {"title": titulo, "body": corpo}}
    if dados:
        mensagem["data"] = {str(k): str(v) for k, v in dados.items()}  # Os valores do payload do FCM precisam ser strings.

    r = requests.post(
        url,
        headers={"Authorization": f"Bearer {creds.token}"},
        json={"message": mensagem},
        timeout=10,
    )
    if r.status_code == 200:
        return True, "enviada"

    # Remove tokens inválidos para não continuar tentando enviar ao mesmo aparelho.
    if r.status_code == 404 and "UNREGISTERED" in r.text:
        supabase.table("dispositivos").delete().eq("fcm_token", fcm_token).eq("usuario_id", _usuario_logado()).execute()
        return False, "aparelho não registrado (token removido)"
    return False, r.text


@app.route("/api/notificacoes/status", methods=["GET"])
def status_firebase():
    """Verifica a configuração do Firebase sem mostrar as credenciais."""
    try:
        from google.oauth2 import service_account

        bruto = os.environ.get("FIREBASE_CREDENTIALS")
        if not bruto:
            return jsonify(firebase="não configurado", detalhe="FIREBASE_CREDENTIALS ausente"), 503
        info = json.loads(bruto)
        service_account.Credentials.from_service_account_info(info, scopes=FCM_SCOPES)
        return jsonify(firebase="ok", project_id=info.get("project_id")), 200
    except Exception as e:
        return jsonify(firebase="erro", detalhe=str(e)), 500


@app.route("/api/dispositivos", methods=["POST"])
def registrar_dispositivo():
    """Registra o token FCM recebido do aplicativo."""
    dados = request.get_json(silent=True) or {}
    usuario_id = dados.get("usuario_id")
    fcm_token = (dados.get("fcm_token") or "").strip()
    negado = _validar_usuario_informado(usuario_id)
    if negado:
        return negado
    usuario_id = _usuario_logado()
    if not fcm_token:
        return jsonify(erro="fcm_token é obrigatório"), 400
    try:
        resp = (
            supabase.table("dispositivos")
            .upsert({"usuario_id": usuario_id, "fcm_token": fcm_token}, on_conflict="fcm_token")
            .execute()
        )
        return jsonify(dispositivo=resp.data[0]), 201
    except Exception as e:
        return erro_banco(e)


@app.route("/api/dispositivos", methods=["DELETE"])
def remover_dispositivo():
    """Desvincula o dispositivo no logout, usando o fcm_token informado."""
    fcm_token = request.args.get("fcm_token", "").strip()
    if not fcm_token:
        return jsonify(erro="fcm_token é obrigatório (?fcm_token=...)"), 400
    try:
        supabase.table("dispositivos").delete().eq("fcm_token", fcm_token).eq("usuario_id", _usuario_logado()).execute()
        return jsonify(mensagem="dispositivo removido"), 200
    except Exception as e:
        return erro_banco(e)


@app.route("/api/notificacoes/enviar", methods=["POST"])
def enviar_notificacao():
    """Envia a mensagem aos dispositivos da conta autenticada."""
    dados = request.get_json(silent=True) or {}
    usuario_id = dados.get("usuario_id")
    titulo = (dados.get("titulo") or "").strip()
    corpo = (dados.get("corpo") or "").strip()
    negado = _validar_usuario_informado(usuario_id)
    if negado:
        return negado
    usuario_id = _usuario_logado()
    if not titulo or not corpo:
        return jsonify(erro="titulo e corpo são obrigatórios"), 400

    try:
        aparelhos = (
            supabase.table("dispositivos").select("fcm_token").eq("usuario_id", usuario_id).execute().data
        )
    except Exception as e:
        return erro_banco(e)

    if not aparelhos:
        return jsonify(erro="esse usuário não tem nenhum aparelho registrado"), 404

    try:
        resultados = [enviar_push(a["fcm_token"], titulo, corpo, dados.get("dados")) for a in aparelhos]
    except Exception as e:
        return jsonify(erro=f"falha ao falar com o Firebase: {e}"), 502

    enviadas = sum(1 for ok, _ in resultados if ok)
    falhas = [detalhe for ok, detalhe in resultados if not ok]
    return jsonify(enviadas=enviadas, falhas=falhas), (200 if enviadas else 502)

# Calendário e progresso, calculados a partir dos dados já cadastrados.


def _periodo_consulta():
    """Limita o intervalo consultado para evitar buscas grandes demais."""
    inicio_bruto = request.args.get("inicio", "")
    fim_bruto = request.args.get("fim", "")
    try:
        inicio = datetime.strptime(inicio_bruto, "%Y-%m-%d").date()
        fim = datetime.strptime(fim_bruto, "%Y-%m-%d").date()
    except ValueError:
        return None, None, "informe inicio e fim no formato AAAA-MM-DD"

    if fim < inicio:
        return None, None, "fim não pode ser anterior a inicio"
    if (fim - inicio).days > 92:
        return None, None, "consulte no máximo 93 dias de cada vez"
    return inicio, fim, None


@app.route("/api/calendario", methods=["GET"])
def consultar_calendario():
    """Combina provas, tarefas e aulas no período solicitado."""
    usuario_id = request.args.get("usuario_id", type=int)
    negado = _validar_usuario_informado(usuario_id)
    if negado:
        return negado
    usuario_id = _usuario_logado()

    inicio, fim, mensagem = _periodo_consulta()
    if mensagem:
        return jsonify(erro=mensagem), 400

    de = f"{inicio.isoformat()}T00:00:00"
    ate = f"{fim.isoformat()}T23:59:59.999999"
    try:
        tarefas = (
            supabase.table("tarefas")
            .select("id, materia_id, titulo, descricao, status, data_entrega, materias!inner(id, usuario_id, nome, cor)")
            .eq("materias.usuario_id", usuario_id)
            .gte("data_entrega", de)
            .lte("data_entrega", ate)
            .order("data_entrega")
            .execute().data
        )
        exames = (
            supabase.table("exames")
            .select("id, materia_id, descricao, data_hora, materias!inner(id, usuario_id, nome, cor)")
            .eq("materias.usuario_id", usuario_id)
            .gte("data_hora", de)
            .lte("data_hora", ate)
            .order("data_hora")
            .execute().data
        )
        materias = (
            supabase.table("materias")
            .select("id, nome, cor, horarios_aula(id, dia_semana, hora_inicio, hora_fim)")
            .eq("usuario_id", usuario_id)
            .execute().data
        )
        eventos = []
        for tarefa in tarefas:
            eventos.append({
                "tipo": "tarefa",
                "id": tarefa["id"],
                "materia_id": tarefa["materia_id"],
                "materia_nome": tarefa["materias"]["nome"],
                "cor": tarefa["materias"]["cor"],
                "titulo": tarefa["titulo"],
                "descricao": tarefa.get("descricao"),
                "data_hora": tarefa["data_entrega"],
                "status": tarefa["status"],
            })
        for exame in exames:
            eventos.append({
                "tipo": "exame",
                "id": exame["id"],
                "materia_id": exame["materia_id"],
                "materia_nome": exame["materias"]["nome"],
                "cor": exame["materias"]["cor"],
                "titulo": "Exame",
                "descricao": exame.get("descricao"),
                "data_hora": exame["data_hora"],
            })
        eventos.sort(key=lambda item: item["data_hora"])
        aulas_semanais = [
            {
                "materia_id": materia["id"],
                "materia_nome": materia["nome"],
                "cor": materia["cor"],
                **horario,
            }
            for materia in materias
            for horario in (materia.get("horarios_aula") or [])
        ]
        return jsonify(
            inicio=inicio.isoformat(),
            fim=fim.isoformat(),
            eventos=eventos,
            aulas_semanais=aulas_semanais,
        ), 200
    except Exception as e:
        return erro_banco(e)


@app.route("/api/progresso", methods=["GET"])
def consultar_progresso():
    """Calcula o progresso com base nas tarefas que já estão no banco."""
    usuario_id = request.args.get("usuario_id", type=int)
    negado = _validar_usuario_informado(usuario_id)
    if negado:
        return negado
    usuario_id = _usuario_logado()

    try:
        materias = (
            supabase.table("materias")
            .select("id, nome, cor")
            .eq("usuario_id", usuario_id)
            .order("nome")
            .execute().data
        )
        tarefas = (
            supabase.table("tarefas")
            .select("id, materia_id, status, data_entrega, materias!inner(usuario_id)")
            .eq("materias.usuario_id", usuario_id)
            .execute().data
        )

        por_materia = {
            materia["id"]: {
                "materia_id": materia["id"],
                "materia_nome": materia["nome"],
                "cor": materia["cor"],
                "total": 0,
                "concluidas": 0,
                "pendentes": 0,
                "vencidas": 0,
                "percentual": 0,
            }
            for materia in materias
        }
        agora_local = agora_do_usuario()
        for tarefa in tarefas:
            resumo = por_materia.get(tarefa["materia_id"])
            if resumo is None:
                continue
            resumo["total"] += 1
            concluida = str(tarefa.get("status", "")).strip().lower() in ("concluida", "concluido")
            if concluida:
                resumo["concluidas"] += 1
            else:
                resumo["pendentes"] += 1
                data_entrega = tarefa.get("data_entrega")
                if data_entrega and data_entrega < agora_local:
                    resumo["vencidas"] += 1

        for resumo in por_materia.values():
            if resumo["total"]:
                resumo["percentual"] = round(100 * resumo["concluidas"] / resumo["total"], 2)

        total = sum(m["total"] for m in por_materia.values())
        concluidas = sum(m["concluidas"] for m in por_materia.values())
        pendentes = sum(m["pendentes"] for m in por_materia.values())
        vencidas = sum(m["vencidas"] for m in por_materia.values())
        return jsonify(
            total=total,
            concluidas=concluidas,
            pendentes=pendentes,
            vencidas=vencidas,
            percentual=round(100 * concluidas / total, 2) if total else 0,
            por_materia=list(por_materia.values()),
        ), 200
    except Exception as e:
        return erro_banco(e)


# As rotas de GPS, QR Code e lembretes ficam em um módulo separado.
from api.recursos import registrar_rotas_complementares
registrar_rotas_complementares(app, supabase, g, request, jsonify, _exigir_propriedade, hash_senha, enviar_push)
