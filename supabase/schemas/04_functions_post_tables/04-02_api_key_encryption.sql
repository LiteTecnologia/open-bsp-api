-- Deterministically hash a plaintext api key using HMAC-SHA256 with a
-- vault-stored secret. Deterministic → same plaintext = same hash → we can
-- look up by equality on api_keys.key_encrypted.
--
-- One-way by design: api keys are credentials we never need to decrypt. On
-- auth we hash the incoming header and compare. On creation, the plaintext is
-- returned to the caller ONCE (see public.create_api_key) and never stored.
-- If the DB leaks, keys cannot be recovered.
--
-- Secret lives in vault.secrets under name 'api_key_encryption_key' (base64).
create or replace function public.encrypt_api_key(plaintext text)
returns bytea
language plpgsql
security definer
set search_path = ''
as $$
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
$$;

-- RPC for UI to create api_keys: takes plaintext, stores the HMAC.
-- Returns the row plus the plaintext ONCE at creation time (UI shows it to user,
-- who must copy it — it won't be recoverable later because we only store the HMAC).
create or replace function public.create_api_key(
  p_organization_id uuid,
  p_role public.role,
  p_name text,
  p_plaintext text
)
returns table (
  id uuid,
  organization_id uuid,
  role public.role,
  name text,
  plaintext text,
  created_at timestamp with time zone
)
language plpgsql
security definer
set search_path = ''
as $$
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
$$;

grant execute on function public.create_api_key to authenticated;
