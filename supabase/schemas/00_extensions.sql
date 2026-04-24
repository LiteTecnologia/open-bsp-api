create extension pg_cron with schema pg_catalog;

create extension moddatetime with schema public;

-- pgcrypto provides extensions.hmac() used by public.encrypt_api_key
-- to deterministically hash api keys for equality-lookup while remaining
-- irreversible (credentials are never decrypted — only HMAC-compared on auth).
create extension if not exists pgcrypto with schema extensions;

/* These extensions are present in new Supabase projects.
create extension pg_net with schema extensions;
create extension pg_graphql with schema graphql;
create extension pg_stat_statements with schema extensions;
create extension supabase_vault with schema vault;
create extension uuid-ossp with schema extensions;
*/
