-- Execute antes de ativar a sincronização offline no Flutter.
begin;

alter table public.horarios_aula
  add column if not exists atualizado_em timestamp without time zone
  not null default (statement_timestamp() at time zone 'UTC');

create or replace function public.atualizar_versao_horario()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.atualizado_em := greatest(
    old.atualizado_em + interval '1 microsecond', clock_timestamp() at time zone 'UTC');
  return new;
end;
$$;

create or replace trigger horarios_aula_atualizado_em
  before update on public.horarios_aula
  for each row execute function public.atualizar_versao_horario();

-- A chave sobrevive à exclusão do registro para um reenvio não recriá-lo.
-- Guardamos a assinatura e o ID, sem duplicar o conteúdo do registro.
create table if not exists public.criacoes_offline (
  usuario_id integer not null references public.usuarios(id) on delete cascade,
  chave uuid not null,
  assinatura bytea not null,
  registro_id bigint not null,
  primary key (usuario_id, chave)
);
alter table public.criacoes_offline enable row level security;
revoke all on table public.criacoes_offline from public, anon, authenticated;

create or replace function public.criar_registro_offline(
    p_usuario_id integer, p_chave uuid, p_tabela text, p_dados jsonb, p_horarios jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_permitidos text[];
  v_colunas text;
  v_dono_sql text;
  v_assinatura bytea;
  v_operacao public.criacoes_offline%rowtype;
  v_registro jsonb;
  v_horarios jsonb;
  v_status integer;
begin
  case p_tabela
    when 'materias' then v_permitidos := array['usuario_id', 'nome', 'professor', 'cor'];
    when 'horarios_aula' then v_permitidos := array['materia_id', 'dia_semana', 'hora_inicio', 'hora_fim'];
    when 'tarefas' then v_permitidos := array['materia_id', 'titulo', 'descricao', 'data_entrega', 'status'];
    when 'exames' then v_permitidos := array['materia_id', 'descricao', 'data_hora'];
    when 'locais' then v_permitidos := array['usuario_id', 'tipo', 'latitude', 'longitude', 'raio_metros'];
    else return jsonb_build_object('status', 400, 'erro', 'recurso inválido');
  end case;

  if jsonb_typeof(p_dados) is distinct from 'object' or p_dados = '{}'::jsonb
      or p_dados - v_permitidos <> '{}'::jsonb
      or jsonb_typeof(p_horarios) is distinct from 'array'
      or (p_tabela <> 'materias' and p_horarios <> '[]'::jsonb) then
    return jsonb_build_object('status', 400, 'erro', 'campos inválidos para este recurso');
  end if;

  if p_tabela in ('materias', 'locais') then
    p_dados := p_dados || jsonb_build_object('usuario_id', p_usuario_id);
    v_dono_sql := 'registro.usuario_id = $2';
  else
    v_dono_sql := 'exists (select 1 from public.materias m where m.id = registro.materia_id and m.usuario_id = $2)';
  end if;

  v_assinatura := sha256(convert_to(jsonb_build_array(p_tabela, p_dados, p_horarios)::text, 'UTF8'));
  -- Serializa reenvios da mesma operação durante a transação de criação.
  perform pg_advisory_xact_lock(hashtextextended(p_usuario_id::text || ':' || p_chave::text, 0));
  select * into v_operacao from public.criacoes_offline
    where usuario_id = p_usuario_id and chave = p_chave;

  if found then
    if v_operacao.assinatura <> v_assinatura then
      return jsonb_build_object('status', 409, 'erro', 'Idempotency-Key já usada em outra criação');
    end if;

    execute format('select to_jsonb(registro) from public.%I registro where registro.id = $1 and %s',
                   p_tabela, v_dono_sql)
      into v_registro using v_operacao.registro_id, p_usuario_id;
    if v_registro is null then
      return jsonb_build_object('status', 410, 'erro', 'registro já foi excluído');
    end if;
    v_status := 200;
  else
    if p_tabela not in ('materias', 'locais') then
      perform 1 from public.materias
        where id = (p_dados->>'materia_id')::integer and usuario_id = p_usuario_id
        for key share;
      if not found then
        return jsonb_build_object('status', 404, 'erro', 'matéria não encontrada');
      end if;
    end if;

    -- Converte pelos tipos da tabela e conserva os defaults de colunas omitidas.
    select string_agg(format('%I', campo), ', ' order by campo) into v_colunas
      from jsonb_object_keys(p_dados) as campos(campo);
    execute format(
      'insert into public.%I as registro (%s) select %s from jsonb_populate_record(null::public.%I, $1) returning to_jsonb(registro)',
      p_tabela, v_colunas, v_colunas, p_tabela)
      into v_registro using p_dados;

    insert into public.criacoes_offline (usuario_id, chave, assinatura, registro_id)
      values (p_usuario_id, p_chave, v_assinatura, (v_registro->>'id')::bigint);
    v_status := 201;
  end if;

  if p_tabela = 'materias' and p_horarios <> '[]'::jsonb then
    if v_status = 201 then
      insert into public.horarios_aula (materia_id, dia_semana, hora_inicio, hora_fim)
        select (v_registro->>'id')::integer, h.dia_semana, h.hora_inicio, h.hora_fim
        from jsonb_to_recordset(p_horarios) as h(dia_semana integer, hora_inicio time, hora_fim time);
    end if;
    select coalesce(jsonb_agg(to_jsonb(h) order by h.id), '[]'::jsonb) into v_horarios
      from public.horarios_aula h where h.materia_id = (v_registro->>'id')::integer;
    v_registro := v_registro || jsonb_build_object('horarios_aula', v_horarios);
  end if;

  return jsonb_build_object('status', v_status, 'registro', v_registro);
exception when unique_violation then
  return jsonb_build_object('status', 409, 'erro', 'já existe um registro com esses dados');
end;
$$;

-- Valida a versão e exclui os dependentes na mesma transação.
create or replace function public.excluir_materia_versionada(
    p_usuario_id integer, p_materia_id integer, p_versao text)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_versao text;
begin
  select to_jsonb(materia)->>'atualizado_em' into v_versao
    from public.materias materia
    where id = p_materia_id and usuario_id = p_usuario_id
    for update;
  if not found then
    return 404;
  end if;
  if v_versao is distinct from p_versao then
    return 409;
  end if;

  delete from public.horarios_aula where materia_id = p_materia_id;
  delete from public.tarefas where materia_id = p_materia_id;
  delete from public.exames where materia_id = p_materia_id;
  delete from public.materias where id = p_materia_id;
  return 200;
end;
$$;

revoke all on function public.criar_registro_offline(integer, uuid, text, jsonb, jsonb)
  from public, anon, authenticated;
revoke all on function public.excluir_materia_versionada(integer, integer, text)
  from public, anon, authenticated;
grant execute on function public.criar_registro_offline(integer, uuid, text, jsonb, jsonb) to service_role;
grant execute on function public.excluir_materia_versionada(integer, integer, text) to service_role;

notify pgrst, 'reload schema';
commit;
