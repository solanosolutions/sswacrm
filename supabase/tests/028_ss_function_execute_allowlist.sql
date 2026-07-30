\set ON_ERROR_STOP on

BEGIN;

DO $$
DECLARE
  v_role TEXT;
  v_function REGPROCEDURE;
  v_allowed TEXT[];
BEGIN
  FOREACH v_role IN ARRAY ARRAY['anon', 'authenticated', 'service_role']
  LOOP
    FOR v_function IN
      SELECT p.oid::regprocedure
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      WHERE n.nspname = 'public'
      ORDER BY p.oid::regprocedure::TEXT
    LOOP
      v_allowed := CASE v_role
        WHEN 'anon' THEN ARRAY[
          'peek_invitation(text)'
        ]
        WHEN 'authenticated' THEN ARRAY[
          'filter_contacts_by_tags(uuid[],text,integer,integer)',
          'is_account_member(uuid,account_role_enum)',
          'peek_invitation(text)',
          'redeem_invitation(text)',
          'remove_account_member(uuid)',
          'set_member_role(uuid,account_role_enum)',
          'touch_presence(text)',
          'transfer_account_ownership(uuid)'
        ]
        WHEN 'service_role' THEN ARRAY[
          'increment_automation_execution_count(uuid)',
          'increment_flow_execution_count(uuid)',
          'is_account_member(uuid,account_role_enum)',
          'recompute_broadcast_counts(uuid)'
        ]
      END;

      IF has_function_privilege(v_role, v_function, 'EXECUTE') <>
         (v_function::TEXT = ANY(v_allowed)) THEN
        RAISE EXCEPTION 'unexpected EXECUTE ACL: role %, function %',
          v_role, v_function;
      END IF;
    END LOOP;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    CROSS JOIN LATERAL
      aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl
    WHERE n.nspname = 'public'
      AND acl.grantee = 0
      AND acl.privilege_type = 'EXECUTE'
  ) THEN
    RAISE EXCEPTION 'PUBLIC retains EXECUTE on a public-schema function';
  END IF;
END
$$;

ROLLBACK;
