/**
 * Supabase 클라이언트
 *
 * service_role 키 사용 → RLS 우회, 서버 전용
 * 사용법:
 *   const supabase = require('./db');
 *   const { data, error } = await supabase.from('scan_jobs').select('*');
 */

const { createClient } = require('@supabase/supabase-js');
const { SUPABASE_URL, SUPABASE_SERVICE_KEY } = require('../config');

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.warn('[DB] SUPABASE_URL 또는 SUPABASE_SERVICE_KEY 가 설정되지 않았습니다. .env 파일을 확인하세요.');
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false },
});

// 연결 테스트
supabase
  .from('scan_jobs')
  .select('id', { count: 'exact', head: true })
  .then(({ error }) => {
    if (error) {
      console.warn('[DB] Supabase 연결 실패:', error.message);
    } else {
      console.log('[DB] Supabase 연결 성공');
    }
  });

module.exports = supabase;
