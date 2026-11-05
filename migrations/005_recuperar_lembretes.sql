-- Execute depois da migration 002 e antes de publicar a API com recuperação de lembretes.
-- A assinatura de quatro parâmetros segue disponível para a versão anterior da API.
begin;

create or replace function public.reservar_notificacao(
    p_usuario_id integer, p_tipo text, p_referencia_id integer, p_janela text,
    p_reservado_em timestamptz)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_id bigint;
begin
  insert into public.notificacoes_processadas as notificacao
    (usuario_id, tipo, referencia_id, janela, status, atualizado_em)
  values (p_usuario_id, p_tipo, p_referencia_id, p_janela, 'processando', p_reservado_em)
  on conflict (usuario_id, tipo, referencia_id, janela)
  do update set status = 'processando', atualizado_em = excluded.atualizado_em
    where notificacao.status in ('falha', 'processando')
      and notificacao.atualizado_em <= now() - interval '10 minutes'
  returning id into v_id;
  return v_id;
end;
$$;

revoke all on function public.reservar_notificacao(integer, text, integer, text, timestamptz)
  from public, anon, authenticated;
grant execute on function public.reservar_notificacao(integer, text, integer, text, timestamptz)
  to service_role;

notify pgrst, 'reload schema';
commit;
