-- SolanoSolutions API key hardening:
--   1. keep api_keys fail-closed to Data API table access;
--   2. expose only safe metadata through authenticated RPCs;
--   3. validate account membership, role and inputs inside the database;
--   4. make revocation one-way and atomic from the client surface.

-- The policies from migration 026 exposed whole rows to members and relied on
-- callers omitting key_hash. Remove every direct client policy: service_role
-- continues to use its explicit table grant and bypasses RLS for API auth.
DROP POLICY IF EXISTS api_keys_select ON public.api_keys;
DROP POLICY IF EXISTS api_keys_insert ON public.api_keys;
DROP POLICY IF EXISTS api_keys_update ON public.api_keys;
DROP POLICY IF EXISTS api_keys_delete ON public.api_keys;

REVOKE ALL PRIVILEGES ON TABLE public.api_keys FROM anon, authenticated;

CREATE OR REPLACE FUNCTION public.list_account_api_keys(
  p_account_id UUID
) RETURNS TABLE (
  id UUID,
  name TEXT,
  key_prefix TEXT,
  scopes TEXT[],
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF auth.uid() IS NULL OR
     NOT public.is_account_member(p_account_id, 'viewer') THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT
    k.id,
    k.name,
    k.key_prefix,
    k.scopes,
    k.last_used_at,
    k.expires_at,
    k.revoked_at,
    k.created_at
  FROM public.api_keys AS k
  WHERE k.account_id = p_account_id
  ORDER BY k.created_at DESC;
END;
$$;

ALTER FUNCTION public.list_account_api_keys(UUID) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.list_account_api_keys(UUID)
FROM PUBLIC, anon, service_role;
GRANT EXECUTE ON FUNCTION public.list_account_api_keys(UUID)
TO authenticated;

CREATE OR REPLACE FUNCTION public.create_account_api_key(
  p_account_id UUID,
  p_name TEXT,
  p_key_prefix TEXT,
  p_key_hash TEXT,
  p_scopes TEXT[] DEFAULT '{}',
  p_expires_at TIMESTAMPTZ DEFAULT NULL
) RETURNS TABLE (
  id UUID,
  name TEXT,
  key_prefix TEXT,
  scopes TEXT[],
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_name TEXT := btrim(p_name);
BEGIN
  IF auth.uid() IS NULL OR
     NOT public.is_account_member(p_account_id, 'admin') THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;

  IF v_name IS NULL OR v_name = '' OR char_length(v_name) > 80 THEN
    RAISE EXCEPTION 'Invalid API key name' USING ERRCODE = '22023';
  END IF;

  IF p_key_prefix IS NULL OR
     p_key_prefix !~ '^wacrm_live_[A-Za-z0-9_-]{8}$' THEN
    RAISE EXCEPTION 'Invalid API key prefix' USING ERRCODE = '22023';
  END IF;

  IF p_key_hash IS NULL OR p_key_hash !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'Invalid API key hash' USING ERRCODE = '22023';
  END IF;

  IF p_scopes IS NULL OR
     cardinality(p_scopes) > 6 OR
     EXISTS (
       SELECT 1
       FROM unnest(p_scopes) AS requested(scope)
       WHERE requested.scope NOT IN (
         'messages:send',
         'messages:read',
         'contacts:read',
         'contacts:write',
         'conversations:read',
         'broadcasts:send'
       )
     ) THEN
    RAISE EXCEPTION 'Invalid API key scopes' USING ERRCODE = '22023';
  END IF;

  IF p_expires_at IS NOT NULL AND
     (p_expires_at <= statement_timestamp() OR
      p_expires_at > statement_timestamp() + INTERVAL '365 days') THEN
    RAISE EXCEPTION 'Invalid API key expiry' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  INSERT INTO public.api_keys (
    account_id,
    created_by,
    name,
    key_prefix,
    key_hash,
    scopes,
    expires_at
  ) VALUES (
    p_account_id,
    auth.uid(),
    v_name,
    p_key_prefix,
    p_key_hash,
    p_scopes,
    p_expires_at
  )
  RETURNING
    api_keys.id,
    api_keys.name,
    api_keys.key_prefix,
    api_keys.scopes,
    api_keys.last_used_at,
    api_keys.expires_at,
    api_keys.revoked_at,
    api_keys.created_at;
END;
$$;

ALTER FUNCTION public.create_account_api_key(UUID, TEXT, TEXT, TEXT, TEXT[], TIMESTAMPTZ)
OWNER TO postgres;
REVOKE ALL ON FUNCTION public.create_account_api_key(UUID, TEXT, TEXT, TEXT, TEXT[], TIMESTAMPTZ)
FROM PUBLIC, anon, service_role;
GRANT EXECUTE ON FUNCTION public.create_account_api_key(UUID, TEXT, TEXT, TEXT, TEXT[], TIMESTAMPTZ)
TO authenticated;

CREATE OR REPLACE FUNCTION public.revoke_account_api_key(
  p_account_id UUID,
  p_key_id UUID
) RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_revoked_id UUID;
BEGIN
  IF auth.uid() IS NULL OR
     NOT public.is_account_member(p_account_id, 'admin') THEN
    RAISE EXCEPTION 'Forbidden' USING ERRCODE = '42501';
  END IF;

  UPDATE public.api_keys
  SET revoked_at = statement_timestamp()
  WHERE id = p_key_id
    AND account_id = p_account_id
    AND revoked_at IS NULL
  RETURNING id INTO v_revoked_id;

  RETURN v_revoked_id IS NOT NULL;
END;
$$;

ALTER FUNCTION public.revoke_account_api_key(UUID, UUID) OWNER TO postgres;
REVOKE ALL ON FUNCTION public.revoke_account_api_key(UUID, UUID)
FROM PUBLIC, anon, service_role;
GRANT EXECUTE ON FUNCTION public.revoke_account_api_key(UUID, UUID)
TO authenticated;
