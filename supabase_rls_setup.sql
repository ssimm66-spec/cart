-- ============================================================
-- RLS + RPC 보안 설정
-- Supabase 대시보드 → SQL Editor 에서 실행하세요.
-- ============================================================

-- 1. 모든 테이블에 RLS 활성화
ALTER TABLE leaders       ENABLE ROW LEVEL SECURITY;
ALTER TABLE members       ENABLE ROW LEVEL SECURITY;
ALTER TABLE events        ENABLE ROW LEVEL SECURITY;
ALTER TABLE registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE assignments   ENABLE ROW LEVEL SECURITY;

-- 2. leaders: anon 직접 접근 완전 차단 (정책 없음 = 기본 거부)

-- 3. 나머지 테이블: anon 전체 허용 (앱 기능에 필요)
CREATE POLICY "anon_members"       ON members       FOR ALL TO anon USING (true) WITH CHECK (true);
CREATE POLICY "anon_events"        ON events        FOR ALL TO anon USING (true) WITH CHECK (true);
CREATE POLICY "anon_registrations" ON registrations FOR ALL TO anon USING (true) WITH CHECK (true);
CREATE POLICY "anon_assignments"   ON assignments   FOR ALL TO anon USING (true) WITH CHECK (true);

-- ============================================================
-- RPC 함수들 (SECURITY DEFINER = anon이 호출해도 서버 권한으로 실행)
-- ============================================================

-- 인도자 이름 존재 여부만 반환 (비밀번호 노출 없음)
CREATE OR REPLACE FUNCTION leader_exists(p_name text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  RETURN EXISTS(SELECT 1 FROM leaders WHERE name = p_name);
END;
$$;

-- 로그인 검증 후 id/name/is_admin만 반환 (비밀번호 제외)
CREATE OR REPLACE FUNCTION check_leader_login(p_name text, p_password text)
RETURNS json LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE result json;
BEGIN
  SELECT row_to_json(l) INTO result
  FROM (SELECT id, name, is_admin FROM leaders
        WHERE name = p_name AND password = p_password) l;
  RETURN result;
END;
$$;

-- 본인 비밀번호 변경 (기존 비밀번호 서버에서 검증)
CREATE OR REPLACE FUNCTION change_leader_password(p_id uuid, p_old_password text, p_new_password text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE cnt int;
BEGIN
  UPDATE leaders SET password = p_new_password
  WHERE id = p_id AND password = p_old_password;
  GET DIAGNOSTICS cnt = ROW_COUNT;
  RETURN cnt > 0;
END;
$$;

-- 인도자 목록 조회 (관리자만, 비밀번호 제외)
CREATE OR REPLACE FUNCTION get_all_leaders(p_requester_id uuid)
RETURNS json LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE is_adm boolean;
BEGIN
  SELECT is_admin INTO is_adm FROM leaders WHERE id = p_requester_id;
  IF NOT COALESCE(is_adm, false) THEN RETURN '[]'::json; END IF;
  RETURN (SELECT COALESCE(json_agg(row_to_json(l)), '[]'::json)
          FROM (SELECT id, name, is_admin FROM leaders ORDER BY name) l);
END;
$$;

-- 인도자 추가 (관리자만)
CREATE OR REPLACE FUNCTION admin_add_leader(p_requester_id uuid, p_name text, p_password text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE is_adm boolean;
BEGIN
  SELECT is_admin INTO is_adm FROM leaders WHERE id = p_requester_id;
  IF NOT COALESCE(is_adm, false) THEN RETURN false; END IF;
  INSERT INTO leaders (name, password) VALUES (p_name, p_password);
  RETURN true;
END;
$$;

-- 인도자 삭제 (관리자만, 본인 삭제 불가)
CREATE OR REPLACE FUNCTION admin_delete_leader(p_requester_id uuid, p_target_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE is_adm boolean;
BEGIN
  SELECT is_admin INTO is_adm FROM leaders WHERE id = p_requester_id;
  IF NOT COALESCE(is_adm, false) THEN RETURN false; END IF;
  IF p_requester_id = p_target_id THEN RETURN false; END IF;
  DELETE FROM leaders WHERE id = p_target_id;
  RETURN true;
END;
$$;

-- 비밀번호 초기화 (관리자만)
CREATE OR REPLACE FUNCTION admin_reset_leader_password(p_requester_id uuid, p_target_id uuid, p_new_password text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE is_adm boolean;
BEGIN
  SELECT is_admin INTO is_adm FROM leaders WHERE id = p_requester_id;
  IF NOT COALESCE(is_adm, false) THEN RETURN false; END IF;
  UPDATE leaders SET password = p_new_password WHERE id = p_target_id;
  RETURN true;
END;
$$;

-- 관리자 권한 토글 (관리자만)
CREATE OR REPLACE FUNCTION admin_toggle_leader_admin(p_requester_id uuid, p_target_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE is_adm boolean;
BEGIN
  SELECT is_admin INTO is_adm FROM leaders WHERE id = p_requester_id;
  IF NOT COALESCE(is_adm, false) THEN RETURN false; END IF;
  UPDATE leaders SET is_admin = NOT is_admin WHERE id = p_target_id;
  RETURN true;
END;
$$;
