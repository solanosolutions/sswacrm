\set ON_ERROR_STOP on

BEGIN;

DO $$
BEGIN
  IF NOT has_schema_privilege('authenticated', 'public', 'USAGE') THEN
    RAISE EXCEPTION 'authenticated lacks USAGE on public';
  END IF;

  IF NOT has_table_privilege('authenticated', 'public.contacts', 'SELECT,INSERT,UPDATE,DELETE') THEN
    RAISE EXCEPTION 'authenticated lacks policy-aligned CRUD on contacts';
  END IF;

  IF has_table_privilege('authenticated', 'public.automation_pending_executions', 'SELECT,INSERT,UPDATE,DELETE') THEN
    RAISE EXCEPTION 'authenticated gained access to service-only automation_pending_executions';
  END IF;

  IF has_table_privilege('authenticated', 'public.api_keys', 'SELECT,INSERT,UPDATE,DELETE') THEN
    RAISE EXCEPTION 'authenticated gained api_keys access before key_hash hardening';
  END IF;

  IF NOT has_table_privilege('service_role', 'public.contacts', 'SELECT,INSERT,UPDATE,DELETE') THEN
    RAISE EXCEPTION 'service_role lacks required CRUD on contacts';
  END IF;

  IF has_table_privilege('authenticated', 'public.contacts', 'TRUNCATE') OR
     has_table_privilege('service_role', 'public.contacts', 'TRUNCATE') THEN
    RAISE EXCEPTION 'runtime role gained TRUNCATE';
  END IF;

  IF EXISTS (
       SELECT 1
       FROM pg_proc p,
            LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
       WHERE p.oid = 'public.recompute_broadcast_counts(uuid)'::regprocedure
         AND acl.grantee = 0
         AND acl.privilege_type = 'EXECUTE'
     ) OR
     has_function_privilege('anon', 'public.recompute_broadcast_counts(uuid)', 'EXECUTE') OR
     has_function_privilege('authenticated', 'public.recompute_broadcast_counts(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'recompute_broadcast_counts remains client-callable';
  END IF;

  IF NOT has_function_privilege('service_role', 'public.recompute_broadcast_counts(uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'service_role cannot run recompute_broadcast_counts';
  END IF;

  IF EXISTS (
       SELECT 1
       FROM pg_proc p,
            LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
       WHERE p.oid = 'public._bcast_bump(uuid,text,integer)'::regprocedure
         AND acl.grantee = 0
         AND acl.privilege_type = 'EXECUTE'
     ) OR
     has_function_privilege('anon', 'public.handle_new_user()', 'EXECUTE') OR
     has_function_privilege('authenticated', 'public.broadcast_recipient_aggregate_trigger()', 'EXECUTE') THEN
    RAISE EXCEPTION 'an internal function remains directly executable';
  END IF;

  IF EXISTS (
       SELECT 1
       FROM pg_proc p,
            LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
       WHERE p.oid = 'public.is_account_member(uuid,account_role_enum)'::regprocedure
         AND acl.grantee = 0
         AND acl.privilege_type = 'EXECUTE'
     ) OR
     has_function_privilege('anon', 'public.is_account_member(uuid,account_role_enum)', 'EXECUTE') THEN
    RAISE EXCEPTION 'membership helper remains anonymously executable';
  END IF;

  IF NOT has_function_privilege('authenticated', 'public.is_account_member(uuid,account_role_enum)', 'EXECUTE') THEN
    RAISE EXCEPTION 'authenticated cannot execute membership helper';
  END IF;

  IF has_function_privilege('anon', 'public.touch_presence(text)', 'EXECUTE') OR
     NOT has_function_privilege('authenticated', 'public.touch_presence(text)', 'EXECUTE') THEN
    RAISE EXCEPTION 'touch_presence role boundary is incorrect';
  END IF;
END
$$;

-- Exercise role boundaries, not only catalog predicates.
SET LOCAL ROLE authenticated;
SELECT count(*) FROM public.contacts;
RESET ROLE;

SET LOCAL ROLE service_role;
SELECT public.recompute_broadcast_counts(
  '00000000-0000-0000-0000-000000000000'::UUID
);
RESET ROLE;

ROLLBACK;
