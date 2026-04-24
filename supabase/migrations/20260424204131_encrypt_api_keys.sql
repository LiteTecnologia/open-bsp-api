-- Ensure pgcrypto is available for extensions.hmac() used by encrypt_api_key.
create extension if not exists pgcrypto with schema extensions;

drop policy "owners can read their orgs api keys" on "public"."api_keys";

alter table "public"."api_keys" drop constraint "api_keys_key_key";

drop index if exists "public"."api_keys_key_key";

alter table "public"."api_keys" drop column "key";

alter table "public"."api_keys" add column "key_encrypted" bytea not null;

CREATE UNIQUE INDEX api_keys_key_encrypted_key ON public.api_keys USING btree (key_encrypted);

alter table "public"."api_keys" add constraint "api_keys_key_encrypted_key" UNIQUE using index "api_keys_key_encrypted_key";

set check_function_bodies = off;

CREATE OR REPLACE FUNCTION public.create_api_key(p_organization_id uuid, p_role public.role, p_name text, p_plaintext text)
 RETURNS TABLE(id uuid, organization_id uuid, role public.role, name text, plaintext text, created_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_row public.api_keys;
begin
  -- Verify caller has owner authority over this org
  if not exists (
    select 1 from public.organizations o
    where o.id = p_organization_id
      and o.id in (select public.get_authorized_orgs('owner'))
  ) then
    raise exception 'not authorized for organization %', p_organization_id
      using errcode = '42501';
  end if;

  insert into public.api_keys (organization_id, role, name, key_encrypted)
  values (p_organization_id, p_role, p_name, public.encrypt_api_key(p_plaintext))
  returning * into v_row;

  return query select
    v_row.id, v_row.organization_id, v_row.role, v_row.name,
    p_plaintext, v_row.created_at;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.encrypt_api_key(plaintext text)
 RETURNS bytea
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  v_key bytea;
begin
  if plaintext is null then
    return null;
  end if;

  select decode(decrypted_secret, 'base64') into v_key
  from vault.decrypted_secrets
  where name = 'api_key_encryption_key';

  if v_key is null then
    raise exception 'api_key_encryption_key not set in vault';
  end if;

  return extensions.hmac(convert_to(plaintext, 'UTF8'), v_key, 'sha256');
end;
$function$
;

CREATE OR REPLACE FUNCTION public.get_authorized_orgs(role public.role DEFAULT 'member'::public.role)
 RETURNS SETOF uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare
  req_level int;
  api_key text;
  org_id uuid;
begin
  req_level := case role::text
    when 'owner' then 3
    when 'admin' then 2
    else 1 -- 'member'
  end;

  -- First, try JWT authentication via auth.uid()
  if auth.uid() is not null then
    return query select organization_id from public.agents
    where
      user_id = auth.uid()
    and (
      extra->'invitation' is null
      or extra->'invitation'->>'status' = 'accepted'
    )
    and (
      case (extra->>'role')
        when 'owner' then 3
        when 'admin' then 2
        else 1 -- 'member'
      end
    ) >= req_level;

    if found then
      return;
    end if;

    raise exception using
      errcode = '42501',
      message = format('insufficient permissions, %s role required', role::text);
  end if;

  -- Fallback to API key authentication
  api_key := current_setting('request.headers', true)::json->>'api-key';

  if api_key is not null then
    select a.organization_id into org_id
    from public.api_keys a
    where a.key_encrypted = public.encrypt_api_key(api_key)
    and (
      case (a.role::text)
        when 'owner' then 3
        when 'admin' then 2
        else 1 -- 'member'
      end
    ) >= req_level;

    if org_id is not null then
      return next org_id;
      return;
    end if;

    raise exception using
      errcode = '42501',
      message = format('invalid api key or insufficient permissions, %s role required', role::text);
  end if;

  raise exception using
    errcode = '42501',
    message = 'authentication required',
    hint = 'use api-key header or jwt authentication';
end;
$function$
;


  create policy "owners can read their orgs api keys"
  on "public"."api_keys"
  as permissive
  for select
  to authenticated, anon
using ((((((current_setting('request.headers'::text, true))::json ->> 'api-key'::text) IS NOT NULL) AND (key_encrypted = public.encrypt_api_key(((current_setting('request.headers'::text, true))::json ->> 'api-key'::text)))) OR (organization_id IN ( SELECT public.get_authorized_orgs('owner'::public.role) AS get_authorized_orgs))));



