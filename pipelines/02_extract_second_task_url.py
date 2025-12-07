"""
Extract second_task_url from translate.goog-wrapped task_url (adult_dedup 전용)

역할:
- adult_dedup 테이블의 task_url에서 translate.goog 프록시를 제거하고
  second_task_url만 채움
- second_task_url_sub는 절대 수정하지 않음
"""

import sqlite3
from urllib.parse import urlparse, urlunparse
import re

# ============================================================
# 🔧 DB / TABLE 설정
# ============================================================
DB_PATH = "db/translate_goog_urls.db"
TABLE_NAME = "adult_dedup"

# ============================================================
# translate.goog 전용 추출 함수
# ============================================================

def _strip_html_suffix_if_domain_like(path: str) -> str:
    """ /amazon.co.jp.html → /amazon.co.jp 로 변환 """
    m = re.fullmatch(r"/((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\.(?:html|htm)", path, re.IGNORECASE)
    if m:
        return "/" + m.group(1)
    return path


def extract_from_translate_goog(url: str):
    """translate.goog 도메인을 원본 도메인으로 되돌리는 함수"""

    if not url:
        return None

    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()

    if "translate.goog" not in host:
        return None

    # 1) translate.goog 앞의 core 텍스트 추출
    core = host.split(".translate.goog", 1)[0]
    if not core:
        return None

    # 2) 단일 하이픈만 점(.)으로 변환
    candidate_host = re.sub(r"(?<!-)-(?!-)", ".", core)

    # 3) 연속 하이픈 → 하나로 축소
    candidate_host = re.sub(r"--+", "-", candidate_host).strip(".")

    if "." not in candidate_host:
        return None

    # path 정리
    path = parsed.path or ""
    if path == "/":
        path = ""
    path = _strip_html_suffix_if_domain_like(path)

    # 최종 URL 구성
    return urlunparse(("https", candidate_host, path, "", "", ""))


# ============================================================
# DB 처리 로직
# ============================================================

def run_extract():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # second_task_url이 비어 있는 행만 처리
    cur.execute(f"""
        SELECT id, task_url
        FROM {TABLE_NAME}
        WHERE second_task_url IS NULL OR second_task_url = ''
    """)

    rows = cur.fetchall()
    processed = 0
    updated = 0

    for row_id, task_url in rows:
        processed += 1

        # translate.goog 해제
        second_url = extract_from_translate_goog(task_url)

        if second_url:
            cur.execute(f"""
                UPDATE {TABLE_NAME}
                SET second_task_url = ?
                WHERE id = ?
            """, (second_url, row_id))
            updated += 1

    conn.commit()
    conn.close()

    return processed, updated


# ============================================================
# 실행부
# ============================================================

if __name__ == "__main__":
    print(f"[INFO] DB Path: {DB_PATH}")
    print(f"[INFO] Table:  {TABLE_NAME}")
    print(f"[INFO] Extracting second_task_url...")

    processed, updated = run_extract()

    print(f"[DONE] Total processed: {processed}")
    print(f"[DONE] Successfully extracted: {updated}")
    print(f"[DONE] Unchanged rows: {processed - updated}")
