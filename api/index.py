import os
import json
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify
import bcrypt
from supabase import create_client, Client

app = Flask(__name__)

# Variáveis de ambiente configuradas no painel da Vercel
# (Project Settings > Environment Variables)
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("Defina SUPABASE_URL e SUPABASE_KEY nas variáveis de ambiente")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


def hash_senha(senha_plana: str) -> str:
    """Gera um hash bcrypt da senha. Nunca guardamos texto plano."""
    return bcrypt.hashpw(senha_plana.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def agora():
    """Agora em UTC (sem fuso) — mesmo padrão do CURRENT_TIMESTAMP do banco. Usado em atualizado_em."""
    return datetime.now(timezone.utc).replace(tzinfo=None).isoformat()


def agora_brasil():
    """
    Agora no horário de Brasília (UTC-3, sem horário de verão desde 2019).
    Usado para comparar com datas digitadas pelo aluno (data_entrega, data_hora),
    que são guardadas sem fuso horário.
    """
    return datetime.now(timezone(timedelta(hours=-3))).replace(tzinfo=None).isoformat()


def erro_banco(e):
    """Traduz erros comuns do Postgres/Supabase para respostas HTTP claras."""
    msg = str(e)
    if "23503" in msg or "foreign key" in msg.lower():
        return jsonify(erro="referência inválida: o id informado (usuário/matéria) não existe"), 400
    if "invalid input value for enum" in msg:
        return jsonify(erro="valor inválido para um campo de opções (ex.: status)"), 400
    return jsonify(erro=msg), 500


def atualizar(tabela, registro_id, dados, permitidos, chave, com_timestamp=True):
    """UPDATE genérico: só altera os campos permitidos que vieram no corpo."""
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
    """DELETE genérico por id."""
    try:
        resp = supabase.table(tabela).delete().eq("id", registro_id).execute()
        if not resp.data:
            return jsonify(erro="registro não encontrado"), 404
        return jsonify(mensagem="apagado com sucesso"), 200
    except Exception as e:
        return erro_banco(e)


@app.after_request
def liberar_cors(response):
    # Equivalente ao middleware cors() do Express — libera o front (Flutter/app)
    # a chamar esses endpoints de outra origem.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
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


@app.route("/api/usuarios/<int:usuario_id>", methods=["PUT"])
def editar_usuario(usuario_id):
    """Edita um usuário existente. Só atualiza os campos que vierem no corpo."""
    dados = request.get_json(silent=True) or {}

    # Monta o dicionário só com o que foi enviado — assim dá pra atualizar
    # apenas o nome, só a senha, ou os três juntos, sem apagar o resto.
    campos_para_atualizar = {}

    if "nome" in dados:
        nome = (dados.get("nome") or "").strip()
        if not nome:
            return jsonify(erro="nome não pode ser vazio"), 400
        campos_para_atualizar["nome"] = nome

    if "email" in dados:
        email = (dados.get("email") or "").strip().lower()
        if not email:
            return jsonify(erro="email não pode ser vazio"), 400
        campos_para_atualizar["email"] = email

    if "senha" in dados:
        senha = dados.get("senha") or ""
        if len(senha) < 6:
            return jsonify(erro="senha deve ter pelo menos 6 caracteres"), 400
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
        return jsonify(erro=msg), 500


@app.route("/api/usuarios/<int:usuario_id>", methods=["DELETE"])
def apagar_usuario(usuario_id):
    """Apaga o usuário e todos os dados dele (matérias, horários, tarefas, exames, locais, preferências)."""
    try:
        materias = supabase.table("materias").select("id").eq("usuario_id", usuario_id).execute().data
        ids = [m["id"] for m in materias]
        if ids:
            for tabela in ("horarios_aula", "tarefas", "exames"):
                supabase.table(tabela).delete().in_("materia_id", ids).execute()
            supabase.table("materias").delete().in_("id", ids).execute()

        supabase.table("locais").delete().eq("usuario_id", usuario_id).execute()
        supabase.table("preferencias_notificacao").delete().eq("usuario_id", usuario_id).execute()
    except Exception as e:
        return erro_banco(e)

    return apagar("usuarios", usuario_id)


# ===============================================================
# MATÉRIAS  (+ horários de aula)
@app.route("/api/materias", methods=["GET"])
def listar_materias():
    """Lista as matérias de um usuário, já com os horários de aula de cada uma."""
    usuario_id = request.args.get("usuario_id", type=int)
    if not usuario_id:
        return jsonify(erro="usuario_id é obrigatório (?usuario_id=1)"), 400
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
    """Cria matéria. Opcionalmente já recebe a lista de horarios de aula."""
    dados = request.get_json(silent=True) or {}
    usuario_id = dados.get("usuario_id")
    nome = (dados.get("nome") or "").strip()
    cor = (dados.get("cor") or "").strip()

    if not usuario_id or not nome or not cor:
        return jsonify(erro="usuario_id, nome e cor são obrigatórios"), 400

    horarios = dados.get("horarios") or []
    for h in horarios:
        if h.get("dia_semana") is None or not h.get("hora_inicio") or not h.get("hora_fim"):
            return jsonify(erro="cada horário precisa de dia_semana, hora_inicio e hora_fim"), 400

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
        if materia:  # não deixa matéria "pela metade" se os horários falharam
            supabase.table("materias").delete().eq("id", materia["id"]).execute()
        return erro_banco(e)


@app.route("/api/materias/<int:materia_id>", methods=["PUT"])
def editar_materia(materia_id):
    dados = request.get_json(silent=True) or {}
    return atualizar("materias", materia_id, dados, ["nome", "professor", "cor"], "materia")


@app.route("/api/materias/<int:materia_id>", methods=["DELETE"])
def apagar_materia(materia_id):
    """Apaga a matéria e tudo que depende dela (horários, tarefas e exames)."""
    try:
        for tabela in ("horarios_aula", "tarefas", "exames"):
            supabase.table(tabela).delete().eq("materia_id", materia_id).execute()
    except Exception as e:
        return erro_banco(e)
    return apagar("materias", materia_id)


@app.route("/api/materias/<int:materia_id>/horarios", methods=["POST"])
def criar_horario(materia_id):
    dados = request.get_json(silent=True) or {}
    if dados.get("dia_semana") is None or not dados.get("hora_inicio") or not dados.get("hora_fim"):
        return jsonify(erro="dia_semana, hora_inicio e hora_fim são obrigatórios"), 400
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


# ===============================================================
# TAREFAS
@app.route("/api/tarefas", methods=["GET"])
def listar_tarefas():
    """
    Lista tarefas de um usuário.
    Filtros opcionais: ?materia_id=3  ?status=pendente  ?vencidas=true
    """
    usuario_id = request.args.get("usuario_id", type=int)
    if not usuario_id:
        return jsonify(erro="usuario_id é obrigatório (?usuario_id=1)"), 400

    try:
        # materias!inner faz o JOIN para filtrar pelo dono da matéria
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
            q = q.eq("status", "pendente").lt("data_entrega", agora_brasil())

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

    novo = {"materia_id": materia_id, "titulo": titulo, "data_entrega": data_entrega}
    if dados.get("descricao") is not None:
        novo["descricao"] = dados["descricao"]
    if dados.get("status"):
        novo["status"] = dados["status"]  # se omitido, o banco usa 'pendente'

    try:
        resp = supabase.table("tarefas").insert(novo).execute()
        return jsonify(tarefa=resp.data[0]), 201
    except Exception as e:
        return erro_banco(e)


@app.route("/api/tarefas/<int:tarefa_id>", methods=["PUT"])
def editar_tarefa(tarefa_id):
    """Serve também para marcar como concluída: {"status": "<valor do enum>"}."""
    dados = request.get_json(silent=True) or {}
    return atualizar(
        "tarefas", tarefa_id, dados,
        ["materia_id", "titulo", "descricao", "data_entrega", "status"], "tarefa",
    )


@app.route("/api/tarefas/<int:tarefa_id>", methods=["DELETE"])
def apagar_tarefa(tarefa_id):
    return apagar("tarefas", tarefa_id)


# ===============================================================
# EXAMES
@app.route("/api/exames", methods=["GET"])
def listar_exames():
    """
    Lista exames de um usuário.
    Filtros opcionais: ?materia_id=3  ?proximos=true (só a partir de agora)
    """
    usuario_id = request.args.get("usuario_id", type=int)
    if not usuario_id:
        return jsonify(erro="usuario_id é obrigatório (?usuario_id=1)"), 400

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
            q = q.gte("data_hora", agora_brasil())

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


# ===============================================================
# NOTIFICAÇÕES PUSH (Firebase Cloud Messaging — API HTTP v1)
# Precisa da variável de ambiente FIREBASE_CREDENTIALS com o JSON da
# service account do Firebase, colado em UMA linha só.

# Verificar na aula caso o Nico não me envie antes.
# ===============================================================
FCM_SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
_fcm_creds = None


def _credenciais_fcm():
    """Carrega (uma vez) as credenciais do Firebase e renova o token de acesso quando expira."""
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
    """Envia uma notificação para UM aparelho. Retorna (ok, detalhe)."""
    import requests

    creds = _credenciais_fcm()
    url = f"https://fcm.googleapis.com/v1/projects/{creds.project_id}/messages:send"
    mensagem = {"token": fcm_token, "notification": {"title": titulo, "body": corpo}}
    if dados:
        mensagem["data"] = {str(k): str(v) for k, v in dados.items()}  # FCM só aceita texto aqui

    r = requests.post(
        url,
        headers={"Authorization": f"Bearer {creds.token}"},
        json={"message": mensagem},
        timeout=10,
    )
    if r.status_code == 200:
        return True, "enviada"

    # Token de aparelho que não existe mais (app desinstalado): remove do banco
    if r.status_code == 404 and "UNREGISTERED" in r.text:
        supabase.table("dispositivos").delete().eq("fcm_token", fcm_token).execute()
        return False, "aparelho não registrado (token removido)"
    return False, r.text


@app.route("/api/notificacoes/status", methods=["GET"])
def status_firebase():
    """Diagnóstico: confirma que a variável FIREBASE_CREDENTIALS foi lida (sem mostrar segredos)."""
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
    """O app chama isso ao abrir/logar, mandando o token FCM do aparelho."""
    dados = request.get_json(silent=True) or {}
    usuario_id = dados.get("usuario_id")
    fcm_token = (dados.get("fcm_token") or "").strip()
    if not usuario_id or not fcm_token:
        return jsonify(erro="usuario_id e fcm_token são obrigatórios"), 400
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
    """O app chama isso no logout: ?fcm_token=..."""
    fcm_token = request.args.get("fcm_token", "").strip()
    if not fcm_token:
        return jsonify(erro="fcm_token é obrigatório (?fcm_token=...)"), 400
    try:
        supabase.table("dispositivos").delete().eq("fcm_token", fcm_token).execute()
        return jsonify(mensagem="dispositivo removido"), 200
    except Exception as e:
        return erro_banco(e)


@app.route("/api/notificacoes/enviar", methods=["POST"])
def enviar_notificacao():
    """Envia uma notificação para todos os aparelhos de um usuário."""
    dados = request.get_json(silent=True) or {}
    usuario_id = dados.get("usuario_id")
    titulo = (dados.get("titulo") or "").strip()
    corpo = (dados.get("corpo") or "").strip()
    if not usuario_id or not titulo or not corpo:
        return jsonify(erro="usuario_id, titulo e corpo são obrigatórios"), 400

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