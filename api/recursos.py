"""Preferências, locais, QR Code, recuperação de senha e lembretes."""
import hashlib
import hmac
import math
import os
import re
import secrets
import smtplib
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
import ssl
from urllib.parse import urlencode, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


PREFERENCIAS_PADRAO = {
    "notif_tarefas": True,
    "notif_exames": True,
    "notif_lembrete_estudo": True,
    "gps_ativo": True,
    "antecedencia_tarefas_minutos": 1440,
    "antecedencia_exames_minutos": 1440,
    "hora_lembrete_estudo": None,
    "fuso_horario": "America/Sao_Paulo",
}


def _validar_preferencias(dados):
    permitidos = set(PREFERENCIAS_PADRAO)
    if not isinstance(dados, dict) or not dados or not set(dados).issubset(permitidos):
        raise ValueError("informe somente campos válidos de preferência")
    for campo in ("notif_tarefas", "notif_exames", "notif_lembrete_estudo", "gps_ativo"):
        if campo in dados and not isinstance(dados[campo], bool):
            raise ValueError(f"{campo} deve ser booleano")
    for campo in ("antecedencia_tarefas_minutos", "antecedencia_exames_minutos"):
        if campo in dados and (type(dados[campo]) is not int or not 0 <= dados[campo] <= 43200):
            raise ValueError(f"{campo} precisa estar entre 0 e 43200 minutos")
    if "hora_lembrete_estudo" in dados and dados["hora_lembrete_estudo"] is not None:
        hora = dados["hora_lembrete_estudo"]
        if not isinstance(hora, str) or not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d)?", hora):
            raise ValueError("hora_lembrete_estudo precisa ter o formato HH:MM")
    if "fuso_horario" in dados:
        nome = dados["fuso_horario"]
        try:
            if not isinstance(nome, str) or len(nome) > 80:
                raise ValueError("fuso horário inválido")
            ZoneInfo(nome)
        except (ZoneInfoNotFoundError, ValueError, KeyError):
            raise ValueError("fuso_horario deve ser um identificador IANA válido") from None
    return dados


def _hora_naive(valor):
    if not isinstance(valor, str):
        raise ValueError("data/hora inválida")
    return datetime.fromisoformat(valor.replace("Z", "+00:00")).replace(tzinfo=None)


def _enviar_email_redefinicao(email_destino, nome, token):
    base = os.environ.get("PASSWORD_RESET_URL", "").strip()
    host = os.environ.get("SMTP_HOST", "").strip()
    remetente = os.environ.get("SMTP_FROM", "").strip()
    if not base.startswith("https://") or not host or not remetente:
        raise RuntimeError("recuperação de senha ainda não configurada")
    separador = "&" if "?" in base else "?"
    link = base + separador + urlencode({"token": token})
    mensagem = EmailMessage()
    mensagem["Subject"] = "Redefinição de senha — StudyTrack"
    mensagem["From"] = remetente
    mensagem["To"] = email_destino
    mensagem.set_content(
        f"Olá, {nome}.\n\nPara criar uma senha nova, abra o link abaixo "
        f"nos próximos 20 minutos:\n{link}\n\nSe não pediu essa alteração, ignore esta mensagem."
    )
    porta = int(os.environ.get("SMTP_PORT", "587"))
    with smtplib.SMTP(host, porta, timeout=10) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        usuario = os.environ.get("SMTP_USER", "")
        senha = os.environ.get("SMTP_PASSWORD", "")
        if usuario:
            smtp.login(usuario, senha)
        smtp.send_message(mensagem)


def _distancia_metros(a_lat, a_lon, b_lat, b_lon):
    r = 6371000
    a1, a2 = math.radians(a_lat), math.radians(b_lat)
    delta_lat = a2 - a1
    delta_lon = math.radians(b_lon - a_lon)
    h = math.sin(delta_lat / 2) ** 2 + math.cos(a1) * math.cos(a2) * math.sin(delta_lon / 2) ** 2
    return round(2 * r * math.asin(min(1, math.sqrt(h))))


def registrar_rotas_complementares(app, supabase, g, request, jsonify, exigir_propriedade, hash_senha, enviar_push):
    def erro_interno(msg):
        app.logger.exception(msg)
        return jsonify(erro="não foi possível concluir a operação"), 503

    def dados_json():
        dados = request.get_json(silent=True)
        return dados if isinstance(dados, dict) else {}

    def prefs_do_usuario(usuario_id):
        linhas = (supabase.table("preferencias_notificacao").select("*")
                  .eq("usuario_id", usuario_id).execute().data)
        return {**PREFERENCIAS_PADRAO, **(linhas[0] if linhas else {}), "usuario_id": usuario_id}

    @app.route("/api/preferencias", methods=["GET"])
    def consultar_preferencias():
        try:
            return jsonify(preferencias=prefs_do_usuario(g.usuario_id)), 200
        except Exception:
            return erro_interno("Erro ao buscar preferências")

    @app.route("/api/preferencias", methods=["PUT"])
    def atualizar_preferencias():
        try:
            dados = _validar_preferencias(dados_json())
        except ValueError as e:
            return jsonify(erro=str(e)), 400
        try:
            anteriores = prefs_do_usuario(g.usuario_id)
            persistir = {campo: anteriores[campo] for campo in PREFERENCIAS_PADRAO}
            persistir.update(dados)
            persistir["usuario_id"] = g.usuario_id
            resp = (supabase.table("preferencias_notificacao")
                    .upsert(persistir, on_conflict="usuario_id").execute())
            return jsonify(preferencias=resp.data[0]), 200
        except Exception:
            return erro_interno("Erro ao salvar preferências")

    @app.route("/api/locais", methods=["GET"])
    def listar_locais():
        try:
            rows = (supabase.table("locais").select("*")
                    .eq("usuario_id", g.usuario_id).execute().data)
            return jsonify(locais=rows), 200
        except Exception:
            return erro_interno("Erro ao listar locais")

    def validar_local(dados, parcial=False):
        permitidos = {"tipo", "latitude", "longitude", "raio_metros"}
        if not dados or not set(dados).issubset(permitidos):
            raise ValueError("envie apenas campos válidos do local")
        for chave in ("tipo", "latitude", "longitude"):
            if not parcial and chave not in dados:
                raise ValueError(f"{chave} é obrigatório")
        if "tipo" in dados and dados["tipo"] not in ("casa", "instituicao"):
            raise ValueError("tipo deve ser 'casa' ou 'instituicao'")
        for chave, limite in (("latitude", 90), ("longitude", 180)):
            if chave in dados:
                try:
                    n = float(dados[chave])
                    if isinstance(dados[chave], bool) or not math.isfinite(n) or not -limite <= n <= limite:
                        raise ValueError()
                    dados[chave] = n
                except (ValueError, TypeError):
                    raise ValueError(f"{chave} está fora do intervalo permitido") from None
        if "raio_metros" in dados and (type(dados["raio_metros"]) is not int or not 25 <= dados["raio_metros"] <= 2000):
            raise ValueError("raio_metros deve estar entre 25 e 2000")
        return dados

    @app.route("/api/locais", methods=["POST"])
    def criar_local():
        try:
            dados = validar_local(dados_json())
        except ValueError as e:
            return jsonify(erro=str(e)), 400
        try:
            dados.update(usuario_id=g.usuario_id)
            return jsonify(local=supabase.table("locais").insert(dados).execute().data[0]), 201
        except Exception:
            return erro_interno("Erro ao cadastrar local; confira os valores permitidos pelo enum locais.tipo")

    def local_do_usuario(local_id):
        rows = (supabase.table("locais").select("*")
                .eq("id", local_id).eq("usuario_id", g.usuario_id).execute().data)
        return rows[0] if rows else None

    @app.route("/api/locais/<int:local_id>", methods=["PUT"])
    def editar_local(local_id):
        try:
            dados = validar_local(dados_json(), parcial=True)
        except ValueError as e:
            return jsonify(erro=str(e)), 400
        try:
            if not local_do_usuario(local_id):
                return jsonify(erro="local não encontrado"), 404
            dados["atualizado_em"] = datetime.now(timezone.utc).isoformat()
            resultado = (supabase.table("locais").update(dados).eq("id", local_id)
                         .eq("usuario_id", g.usuario_id).execute().data)
            return jsonify(local=resultado[0]), 200
        except Exception:
            return erro_interno("Erro ao editar local")

    @app.route("/api/locais/<int:local_id>", methods=["DELETE"])
    def excluir_local(local_id):
        try:
            rows = (supabase.table("locais").delete().eq("id", local_id)
                    .eq("usuario_id", g.usuario_id).execute().data)
            return (jsonify(mensagem="local excluído"), 200) if rows else (jsonify(erro="local não encontrado"), 404)
        except Exception:
            return erro_interno("Erro ao excluir local")

    def eventos_do_dia(usuario_id, dia):
        inicio, fim = f"{dia}T00:00:00", f"{dia}T23:59:59.999999"
        tarefas = (supabase.table("tarefas")
                   .select("id,titulo,data_entrega,status,materia_id,materias!inner(usuario_id,nome)")
                   .eq("materias.usuario_id", usuario_id)
                   .gte("data_entrega", inicio).lte("data_entrega", fim).execute().data)
        exames = (supabase.table("exames")
                  .select("id,descricao,data_hora,materia_id,materias!inner(usuario_id,nome)")
                  .eq("materias.usuario_id", usuario_id)
                  .gte("data_hora", inicio).lte("data_hora", fim).execute().data)
        # O aplicativo e a API usam segunda=1 e domingo=7.
        dia_semana = date.fromisoformat(dia).isoweekday()
        aulas = (supabase.table("horarios_aula")
                 .select("id,dia_semana,hora_inicio,hora_fim,materia_id,materias!inner(usuario_id,nome)")
                 .eq("materias.usuario_id", usuario_id).eq("dia_semana", dia_semana).execute().data)
        return {"tarefas": tarefas, "exames": exames, "aulas": aulas}

    @app.route("/api/compromissos-hoje", methods=["GET"])
    def compromissos_hoje():
        try:
            fuso = ZoneInfo(prefs_do_usuario(g.usuario_id)["fuso_horario"])
            dia = datetime.now(fuso).date().isoformat()
            return jsonify(data=dia, compromissos=eventos_do_dia(g.usuario_id, dia)), 200
        except Exception:
            return erro_interno("Erro ao montar agenda do dia")

    @app.route("/api/gps/chegada", methods=["POST"])
    def verificar_chegada():
        dados = dados_json()
        try:
            local_id = int(dados["local_id"])
            lat, lon = float(dados["latitude"]), float(dados["longitude"])
            if not math.isfinite(lat) or not math.isfinite(lon) or abs(lat) > 90 or abs(lon) > 180:
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            return jsonify(erro="informe local_id, latitude e longitude válidos"), 400
        try:
            prefs = prefs_do_usuario(g.usuario_id)
            if not prefs["gps_ativo"]:
                return jsonify(erro="GPS está desativado nas preferências"), 403
            local = local_do_usuario(local_id)
            if not local:
                return jsonify(erro="local não encontrado"), 404
            distancia = _distancia_metros(lat, lon, float(local["latitude"]), float(local["longitude"]))
            dentro = distancia <= int(local.get("raio_metros") or 200)
            resposta = {"proximo": dentro, "distancia_metros": distancia}
            if dentro:
                dia = datetime.now(ZoneInfo(prefs["fuso_horario"])).date().isoformat()
                resposta.update(data=dia, compromissos=eventos_do_dia(g.usuario_id, dia))
            return jsonify(**resposta), 200
        except Exception:
            return erro_interno("Erro ao verificar proximidade")

    @app.route("/api/qrcodes", methods=["GET"])
    def listar_qrcodes():
        try:
            itens = (supabase.table("codigos_qr")
                     .select("*,materias!inner(usuario_id)")
                     .eq("materias.usuario_id", g.usuario_id).execute().data)
            return jsonify(codigos=itens), 200
        except Exception:
            return erro_interno("Erro ao consultar códigos QR")

    @app.route("/api/qrcodes", methods=["POST"])
    def criar_qrcode():
        dados = dados_json()
        try:
            materia_id = int(dados["materia_id"])
            tipo = dados["tipo"]
            titulo = dados["titulo"].strip()
            if tipo not in ("material", "tarefa", "exame") or not titulo or len(titulo) > 150:
                raise ValueError()
            if tipo == "material":
                url = dados["url"].strip()
                endereco = urlparse(url)
                if endereco.scheme != "https" or not endereco.netloc or endereco.username or endereco.password:
                    raise ValueError()
                referencia_id = None
            else:
                url = None
                referencia_id = int(dados["referencia_id"])
                if referencia_id <= 0:
                    raise ValueError()
        except (KeyError, TypeError, ValueError, AttributeError):
            return jsonify(erro="informe matéria, título e URL https (material) ou referencia_id (tarefa/exame)"), 400
        negado = exigir_propriedade("materias", materia_id)
        if negado:
            return negado
        if tipo != "material":
            negado = exigir_propriedade("tarefas" if tipo == "tarefa" else "exames", referencia_id)
            if negado:
                return negado
            # Não permite associar uma tarefa ou prova de outra matéria ao QR Code.
            try:
                item = (supabase.table("tarefas" if tipo == "tarefa" else "exames")
                        .select("materia_id").eq("id", referencia_id).execute().data)
                if not item or item[0]["materia_id"] != materia_id:
                    return jsonify(erro="referência não pertence à matéria selecionada"), 400
            except Exception:
                return erro_interno("Erro ao validar referência do QR")
        try:
            item = {"materia_id": materia_id, "codigo": secrets.token_urlsafe(24),
                    "tipo": tipo, "titulo": titulo, "url": url, "referencia_id": referencia_id}
            return jsonify(codigo=supabase.table("codigos_qr").insert(item).execute().data[0]), 201
        except Exception:
            return erro_interno("Erro ao cadastrar QR")

    @app.route("/api/qrcodes/<string:codigo>", methods=["GET"])
    def resolver_qrcode(codigo):
        if len(codigo) > 128:
            return jsonify(erro="código inválido"), 400
        try:
            rows = (supabase.table("codigos_qr")
                    .select("*,materias!inner(usuario_id)")
                    .eq("codigo", codigo).eq("materias.usuario_id", g.usuario_id).execute().data)
            if not rows:
                return jsonify(erro="código não encontrado"), 404
            item = rows[0]
            if item["tipo"] in ("tarefa", "exame"):
                tabela = "tarefas" if item["tipo"] == "tarefa" else "exames"
                referencia = (supabase.table(tabela).select("id,materia_id")
                              .eq("id", item["referencia_id"]).eq("materia_id", item["materia_id"])
                              .execute().data)
                if not referencia:
                    return jsonify(erro="atividade ou avaliação não está mais disponível"), 404
            return jsonify(codigo=item), 200
        except Exception:
            return erro_interno("Erro ao ler QR")

    @app.route("/api/qrcodes/<string:codigo>/registrar", methods=["POST"])
    def registrar_leitura_qr(codigo):
        if len(codigo) > 128:
            return jsonify(erro="código inválido"), 400
        try:
            encontrados = (supabase.table("codigos_qr")
                           .select("*,materias!inner(usuario_id)")
                           .eq("codigo", codigo).eq("materias.usuario_id", g.usuario_id).execute().data)
            if not encontrados:
                return jsonify(erro="código não encontrado"), 404
            item = encontrados[0]
            if item["tipo"] in ("tarefa", "exame"):
                tabela = "tarefas" if item["tipo"] == "tarefa" else "exames"
                referencia = (supabase.table(tabela).select("id,materia_id")
                              .eq("id", item["referencia_id"]).eq("materia_id", item["materia_id"])
                              .execute().data)
                if not referencia:
                    return jsonify(erro="atividade ou avaliação não está mais disponível"), 404
            registro = {"usuario_id": g.usuario_id, "codigo_qr_id": item["id"]}
            leitura = supabase.table("leituras_qr").insert(registro).execute().data[0]
            return jsonify(leitura=leitura, codigo=item), 201
        except Exception:
            return erro_interno("Erro ao registrar leitura de QR")

    @app.route("/api/qrcodes/<int:codigo_id>", methods=["DELETE"])
    def apagar_qrcode(codigo_id):
        try:
            rows = (supabase.table("codigos_qr")
                    .select("id,materias!inner(usuario_id)").eq("id", codigo_id)
                    .eq("materias.usuario_id", g.usuario_id).execute().data)
            if not rows:
                return jsonify(erro="código não encontrado"), 404
            supabase.table("codigos_qr").delete().eq("id", codigo_id).execute()
            return jsonify(mensagem="código removido"), 200
        except Exception:
            return erro_interno("Erro ao apagar QR")

    @app.route("/api/auth/recuperar-senha", methods=["POST"])
    def solicitar_redefinicao():
        email = dados_json().get("email", "")
        email = email.strip().lower() if isinstance(email, str) else ""
        if not email or len(email) > 254 or "@" not in email:
            return jsonify(erro="informe um e-mail válido"), 400
        if not (os.environ.get("SMTP_HOST") and os.environ.get("SMTP_FROM") and
                os.environ.get("PASSWORD_RESET_URL", "").startswith("https://")):
            return jsonify(erro="recuperação de senha ainda não configurada"), 503
        resposta = {"mensagem": "se a conta existir, enviaremos instruções para o e-mail cadastrado"}
        try:
            usuarios = (supabase.table("usuarios").select("id,nome,email")
                        .eq("email", email).execute().data)
            if not usuarios:
                return jsonify(**resposta), 200
            usuario = usuarios[0]
            recente = (supabase.table("tokens_redefinicao_senha").select("token_hash")
                      .eq("usuario_id", usuario["id"])
                      .gte("criado_em", (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat())
                      .execute().data)
            if recente:
                return jsonify(**resposta), 200
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            supabase.table("tokens_redefinicao_senha").insert({
                "token_hash": token_hash, "usuario_id": usuario["id"],
                "expira_em": (datetime.now(timezone.utc) + timedelta(minutes=20)).isoformat(),
            }).execute()
            try:
                _enviar_email_redefinicao(email, usuario["nome"], token)
            except Exception:
                app.logger.exception("Falha ao enviar e-mail de recuperação")
                supabase.table("tokens_redefinicao_senha").delete().eq("token_hash", token_hash).execute()
            return jsonify(**resposta), 200
        except Exception:
            return erro_interno("Erro na solicitação de recuperação de senha")

    @app.route("/api/auth/redefinir-senha", methods=["POST"])
    def redefinir_senha():
        dados = dados_json()
        token = dados.get("token")
        nova_senha = dados.get("nova_senha")
        if (not isinstance(token, str) or not 20 <= len(token) <= 256
                or not isinstance(nova_senha, str) or len(nova_senha) < 8
                or len(nova_senha.encode("utf-8")) > 72):
            return jsonify(erro="token inválido ou senha fora do intervalo de 8 a 72 bytes"), 400
        try:
            digest = hashlib.sha256(token.encode()).hexdigest()
            resultado = supabase.rpc("consumir_token_redefinicao", {
                "p_token_hash": digest, "p_novo_hash": hash_senha(nova_senha)
            }).execute().data
            if resultado is not True:
                return jsonify(erro="token inválido, expirado ou já utilizado"), 400
            return jsonify(mensagem="senha redefinida; faça login novamente"), 200
        except Exception:
            return erro_interno("Erro ao redefinir senha")

    @app.route("/api/interno/processar-lembretes", methods=["POST"])
    def processar_lembretes():
        segredo = os.environ.get("CRON_SECRET", "")
        informado = request.headers.get("X-Cron-Secret", "")
        if len(segredo) < 32:
            return jsonify(erro="agendador não configurado"), 503
        if not isinstance(informado, str) or not hmac.compare_digest(segredo, informado):
            return jsonify(erro="não autorizado"), 401

        instante = datetime.now(timezone.utc)
        resultados = {"candidatos": 0, "enviados": 0, "falhas": 0, "ignorados": 0}
        try:
            # O agendador chama esta rota a cada 15 minutos; a API não fica rodando continuamente.
            usuarios = supabase.table("usuarios").select("id,nome").execute().data
            for usuario in usuarios:
                usuario_id = usuario["id"]
                preferencias = prefs_do_usuario(usuario_id)
                local_agora = instante.astimezone(ZoneInfo(preferencias["fuso_horario"]))
                dispositivos = (supabase.table("dispositivos").select("fcm_token")
                                .eq("usuario_id", usuario_id).execute().data)
                if not dispositivos:
                    continue
                candidatos = []
                for tipo, tabela, coluna, ligado, minutos in (
                    ("tarefa", "tarefas", "data_entrega", "notif_tarefas", "antecedencia_tarefas_minutos"),
                    ("exame", "exames", "data_hora", "notif_exames", "antecedencia_exames_minutos"),
                ):
                    if not preferencias[ligado]:
                        continue
                    antecedencia = int(preferencias[minutos])
                    de = (local_agora + timedelta(minutes=antecedencia)).replace(tzinfo=None)
                    ate = (local_agora + timedelta(minutes=antecedencia + 15)).replace(tzinfo=None)
                    consulta = (supabase.table(tabela)
                                .select(f"id,materia_id,{coluna},materias!inner(usuario_id,nome)")
                                .eq("materias.usuario_id", usuario_id)
                                .gte(coluna, de.isoformat()).lte(coluna, ate.isoformat()))
                    if tipo == "tarefa":
                        consulta = consulta.eq("status", "pendente")
                    for evento in consulta.execute().data:
                        instante_evento = _hora_naive(evento[coluna])
                        minutos_ate = (instante_evento - local_agora.replace(tzinfo=None)).total_seconds() / 60
                        if not antecedencia <= minutos_ate < antecedencia + 15:
                            continue
                        candidatos.append((tipo, evento["id"], f"{evento[coluna]}:{antecedencia}",
                            f"{'Tarefa' if tipo == 'tarefa' else 'Prova'} de {evento['materias']['nome']}",
                            f"Faltam cerca de {antecedencia // 60} horas para o prazo."))
                hora_estudo = preferencias.get("hora_lembrete_estudo")
                if preferencias["notif_lembrete_estudo"] and hora_estudo:
                    h, m = map(int, hora_estudo[:5].split(":"))
                    horario = local_agora.replace(hour=h, minute=m, second=0, microsecond=0)
                    decorrido = (local_agora - horario).total_seconds() / 60
                    if 0 <= decorrido < 15:
                        candidatos.append(("estudo", 0, f"{local_agora.date()}:{hora_estudo}",
                                           "Hora de estudar", "Reserve um momento para revisar suas matérias."))
                for tipo, ref_id, janela, titulo, corpo in candidatos:
                    resultados["candidatos"] += 1
                    claim = supabase.rpc("reservar_notificacao", {
                        "p_usuario_id": usuario_id, "p_tipo": tipo,
                        "p_referencia_id": ref_id, "p_janela": janela,
                    }).execute().data
                    if claim is None:
                        resultados["ignorados"] += 1
                        continue
                    sucesso = 0
                    for dispositivo in dispositivos:
                        try:
                            ok, _ = enviar_push(dispositivo["fcm_token"], titulo, corpo,
                                                {"tipo": tipo, "referencia_id": str(ref_id)})
                            if ok:
                                sucesso += 1
                        except Exception:
                            app.logger.exception("Erro no envio de push")
                    status = "enviado" if sucesso else "falha"
                    atualizacao = {"status": status, "atualizado_em": instante.isoformat()}
                    if sucesso:
                        atualizacao["enviado_em"] = instante.isoformat()
                    supabase.table("notificacoes_processadas").update(atualizacao).eq("id", claim).execute()
                    resultados["enviados" if sucesso else "falhas"] += 1
            return jsonify(**resultados), 200
        except Exception:
            return erro_interno("Falha ao processar lembretes")