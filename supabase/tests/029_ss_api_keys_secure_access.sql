\set ON_ERROR_STOP on

BEGIN;

DO $$
BEGIN
  IF has_table_privilege('authenticated', 'public.api_keys', 'SELECT,INSERT,UPDATE,DELETE') THEN
    RAISE EXCEPTION 'authenticated has direct api_keys table access';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'api_keys'
  ) THEN
    RAISE EXCEPTION 'api_keys still has a direct client policy';
  END IF;

  IF has_function_privilege('anon', 'public.list_account_api_keys(uuid)', 'EXECUTE') OR
     has_function_privilege('anon', 'public.create_account_api_key(uuid,text,text,text,text[],timestamp with time zone)', 'EXECUTE') OR
     has_function_privilege('anon', 'public.revoke_account_api_key(uuid,uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'anon can execute an API key management RPC';
  END IF;

  IF NOT has_function_privilege('authenticated', 'public.list_account_api_keys(uuid)', 'EXECUTE') OR
     NOT has_function_privilege('authenticated', 'public.create_account_api_key(uuid,text,text,text,text[],timestamp with time zone)', 'EXECUTE') OR
     NOT has_function_privilege('authenticated', 'public.revoke_account_api_key(uuid,uuid)', 'EXECUTE') THEN
    RAISE EXCEPTION 'authenticated lacks an API key management RPC';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.parameters
    WHERE specific_schema = 'public'
      AND specific_name LIKE ANY (ARRAY[
        'list_account_api_keys_%',
        'create_account_api_key_%'
      ])
      AND parameter_mode IN ('OUT', 'INOUT')
      AND parameter_name = 'key_hash'
  ) THEN
    RAISE EXCEPTION 'an API key management RPC exposes key_hash';
  END IF;
END
$$;

-- Runtime role cannot bypass the RPC surface with direct table access.
SET LOCAL ROLE authenticated;
DO $$
BEGIN
  PERFORM key_hash FROM public.api_keys LIMIT 1;
  RAISE EXCEPTION 'authenticated unexpectedly selected key_hash';
EXCEPTION
  WHEN insufficient_privilege THEN NULL;
END
$$;
RESET ROLE;

-- Create disposable identities. The signup trigger creates one account/profile
-- per user; the viewer is then moved into the admin's account for role tests.
INSERT INTO auth.users (
  instance_id,
  id,
  aud,
  role,
  email,
  encrypted_password,
  email_confirmed_at,
  raw_app_meta_data,
  raw_user_meta_data,
  created_at,
  updated_at
) VALUES
  (
    '00000000-0000-0000-0000-000000000000',
    '10000000-0000-0000-0000-000000000001',
    'authenticated',
    'authenticated',
    'api-admin-test@example.invalid',
    '',
    statement_timestamp(),
    '{}',
    '{"full_name":"API Admin Test"}',
    statement_timestamp(),
    statement_timestamp()
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    '10000000-0000-0000-0000-000000000002',
    'authenticated',
    'authenticated',
    'api-viewer-test@example.invalid',
    '',
    statement_timestamp(),
    '{}',
    '{"full_name":"API Viewer Test"}',
    statement_timestamp(),
    statement_timestamp()
  ),
  (
    '00000000-0000-0000-0000-000000000000',
    '10000000-0000-0000-0000-000000000003',
    'authenticated',
    'authenticated',
    'api-outsider-test@example.invalid',
    '',
    statement_timestamp(),
    '{}',
    '{"full_name":"API Outsider Test"}',
    statement_timestamp(),
    statement_timestamp()
  );

DO $$
DECLARE
  v_admin_account_id UUID;
  v_viewer_old_account_id UUID;
  v_outsider_account_id UUID;
BEGIN
  SELECT account_id INTO v_admin_account_id
  FROM public.profiles
  WHERE user_id = '10000000-0000-0000-0000-000000000001';

  SELECT account_id INTO v_viewer_old_account_id
  FROM public.profiles
  WHERE user_id = '10000000-0000-0000-0000-000000000002';

  SELECT account_id INTO v_outsider_account_id
  FROM public.profiles
  WHERE user_id = '10000000-0000-0000-0000-000000000003';

  UPDATE public.profiles
  SET account_id = v_admin_account_id,
      account_role = 'viewer'
  WHERE user_id = '10000000-0000-0000-0000-000000000002';

  DELETE FROM public.accounts WHERE id = v_viewer_old_account_id;

  PERFORM set_config('test.admin_account_id', v_admin_account_id::TEXT, true);
  PERFORM set_config('test.outsider_account_id', v_outsider_account_id::TEXT, true);
END
$$;

SET LOCAL ROLE authenticated;
SELECT set_config(
  'request.jwt.claim.sub',
  '10000000-0000-0000-0000-000000000001',
  true
);

DO $$
DECLARE
  v_created JSONB;
BEGIN
  SELECT to_jsonb(created)
  INTO v_created
  FROM public.create_account_api_key(
    current_setting('test.admin_account_id')::UUID,
    '  Integration test  ',
    'wacrm_live_Abcd_123',
    repeat('a', 64),
    ARRAY['contacts:read'],
    statement_timestamp() + INTERVAL '1 day'
  ) AS created;

  IF v_created IS NULL OR
     v_created ? 'key_hash' OR
     v_created->>'name' <> 'Integration test' THEN
    RAISE EXCEPTION 'create RPC returned an unsafe or invalid payload';
  END IF;

  PERFORM set_config('test.key_id', v_created->>'id', true);

  BEGIN
    PERFORM public.create_account_api_key(
      current_setting('test.admin_account_id')::UUID,
      'Invalid hash',
      'wacrm_live_Abcd_456',
      'not-a-hash',
      ARRAY['contacts:read'],
      NULL
    );
    RAISE EXCEPTION 'create RPC accepted an invalid hash';
  EXCEPTION
    WHEN invalid_parameter_value THEN NULL;
  END;

  BEGIN
    PERFORM public.create_account_api_key(
      current_setting('test.admin_account_id')::UUID,
      'Invalid scope',
      'wacrm_live_Abcd_789',
      repeat('b', 64),
      ARRAY['admin:all'],
      NULL
    );
    RAISE EXCEPTION 'create RPC accepted an unknown scope';
  EXCEPTION
    WHEN invalid_parameter_value THEN NULL;
  END;
END
$$;

-- A viewer can list safe metadata for their own account, but cannot create,
-- revoke or enumerate another account.
SELECT set_config(
  'request.jwt.claim.sub',
  '10000000-0000-0000-0000-000000000002',
  true
);

DO $$
DECLARE
  v_count INTEGER;
BEGIN
  SELECT count(*) INTO v_count
  FROM public.list_account_api_keys(
    current_setting('test.admin_account_id')::UUID
  );

  IF v_count <> 1 THEN
    RAISE EXCEPTION 'viewer could not list safe metadata for own account';
  END IF;

  BEGIN
    PERFORM public.list_account_api_keys(
      current_setting('test.outsider_account_id')::UUID
    );
    RAISE EXCEPTION 'viewer listed another account API keys';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM public.create_account_api_key(
      current_setting('test.admin_account_id')::UUID,
      'Viewer key',
      'wacrm_live_Viewer01',
      repeat('c', 64),
      ARRAY[]::TEXT[],
      NULL
    );
    RAISE EXCEPTION 'viewer created an API key';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;

  BEGIN
    PERFORM public.revoke_account_api_key(
      current_setting('test.admin_account_id')::UUID,
      current_setting('test.key_id')::UUID
    );
    RAISE EXCEPTION 'viewer revoked an API key';
  EXCEPTION
    WHEN insufficient_privilege THEN NULL;
  END;
END
$$;

-- Admin revocation is account-scoped, one-way and idempotent.
SELECT set_config(
  'request.jwt.claim.sub',
  '10000000-0000-0000-0000-000000000001',
  true
);

DO $$
BEGIN
  IF public.revoke_account_api_key(
       current_setting('test.outsider_account_id')::UUID,
       current_setting('test.key_id')::UUID
     ) THEN
    RAISE EXCEPTION 'admin revoked a key through another account context';
  END IF;
EXCEPTION
  WHEN insufficient_privilege THEN NULL;
END
$$;

DO $$
BEGIN
  IF NOT public.revoke_account_api_key(
       current_setting('test.admin_account_id')::UUID,
       current_setting('test.key_id')::UUID
     ) THEN
    RAISE EXCEPTION 'admin could not revoke own account key';
  END IF;

  IF public.revoke_account_api_key(
       current_setting('test.admin_account_id')::UUID,
       current_setting('test.key_id')::UUID
     ) THEN
    RAISE EXCEPTION 'second revocation was not idempotent';
  END IF;
END
$$;
RESET ROLE;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.api_keys
    WHERE id = current_setting('test.key_id')::UUID
      AND (created_by <> '10000000-0000-0000-0000-000000000001' OR
           revoked_at IS NULL)
  ) THEN
    RAISE EXCEPTION 'created_by or revoked_at invariant failed';
  END IF;
END
$$;

ROLLBACK;
