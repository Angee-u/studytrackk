"""Controles opcionais para as escritas que chegam do cache SQLite."""

from datetime import datetime
from uuid import UUID


def criar_com_chave(supabase, request, jsonify, usuario_id, tabela, dados, chave_resposta, *, horarios=()):
    chave = request.headers.get("Idempotency-Key")
    if chave is None:
        return None
    try:
        chave = str(UUID(chave))
    except ValueError:
        return jsonify(erro="Idempotency-Key deve ser um UUID"), 400

    resultado = supabase.rpc("criar_registro_offline", {
        "p_usuario_id": usuario_id, "p_chave": chave, "p_tabela": tabela,
        "p_dados": dados, "p_horarios": list(horarios),
    }).execute().data
    status = resultado["status"]
    if "erro" in resultado:
        return jsonify(erro=resultado["erro"]), status
    return jsonify({chave_resposta: resultado["registro"]}), status


def versao_informada(request):
    versao = request.headers.get("X-Registro-Versao")
    if versao is None:
        return None
    try:
        if len(versao) > 40 or "T" not in versao:
            raise ValueError()
        datetime.fromisoformat(versao)
    except ValueError:
        raise ValueError("X-Registro-Versao deve conter o atualizado_em recebido da API") from None
    return versao
