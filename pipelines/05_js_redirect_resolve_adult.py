# -*- coding: utf-8 -*-
"""
adult_dedup 전용: JS 기반 리디렉션 추적기

역할
- DB: db/translate_goog_urls.db
- 테이블: adult_dedup
- 입력 컬럼: second_task_url
- 출력 컬럼: script_redirect_url2

동작
- Playwright(Chromium headless)를 사용해 second_task_url로 실제 브라우저 접속
- DOM 로드 + 일정 시간(wait_ms) 대기 → JS/메타 리디렉션이 실행되도록 함
- 그 시점의 page.url을 최종 렌딩 URL로 보고 script_redirect_url2에 저장
- 진행 상황은 tqdm 막대기로 표시하고,
  각 URL의 리디렉션 결과는 [OK]/[ERR] 한 줄 로그로 미리보기 제공

  # 소규모 테스트 (예: 20개만, 2초 대기)
python pipelines/05_js_redirect_resolve_adult.py --limit 20 --wait-ms 2000

# 전체 돌릴 때 (기존 값은 유지하고 빈 것만 채우기)
python pipelines/05_js_redirect_resolve_adult.py

# 이미 채워진 것도 전부 다시 덮어쓰고 싶을 때
python pipelines/05_js_redirect_resolve_adult.py --overwrite

"""

from __future__ import annotations
import argparse
import sqlite3
from typing import List, Tuple

from playwright.sync_api import sync_playwright

# tqdm: 진행 막대 + 로그 출력용
try:
    from tqdm import tqdm
except ImportError:  # pragma: no cover
    # tqdm이 없을 때 매우 간단한 fallback
    class tqdm:  # type: ignore
        def __init__(self, iterable=None, total=None, desc=None):
            self.iterable = iterable or range(total or 0)
            self.total = total or len(self.iterable)
            self.n = 0
            self.desc = desc or "progress"
            print(f"[{self.desc}] 시작 (0/{self.total})")
        def __iter__(self):
            for x in self.iterable:
                yield x
                self.n += 1
                if self.n % 100 == 0 or self.n == self.total:
                    print(f"[{self.desc}] 진행: {self.n}/{self.total}")
        def update(self, n=1):
            self.n += n
        @staticmethod
        def write(s: str):
            print(s)
        def set_postfix(self, **kwargs):
            pass
        def close(self):
            print(f"[{self.desc}] 완료 ({self.n}/{self.total})")


# --- 기본 설정값 (필요하면 여기만 수정) ---
DB_PATH = "db/translate_goog_urls.db"
TABLE_NAME = "adult_dedup"
IN_COL = "second_task_url"         # 중간 랜딩 (ru.com 등)
OUT_COL = "script_redirect_url2"   # 최종 JS 리디렉션 결과 URL 저장 위치


# ------------------------------------------------------------
# DB 유틸
# ------------------------------------------------------------
def verify_table(conn: sqlite3.Connection, table: str):
    """adult_dedup 테이블에 필요한 컬럼이 있는지 점검."""
    cur = conn.execute(f"PRAGMA table_info('{table}')")
    cols = {row[1] for row in cur}
    required = {"id", IN_COL, OUT_COL}
    missing = required - cols
    if missing:
        raise RuntimeError(f"테이블 '{table}'에 필요한 컬럼이 없습니다: {missing}")
    print(f"[i] 테이블 '{table}' 및 컬럼 점검 완료: {sorted(cols)}")


def fetch_rows(conn: sqlite3.Connection, overwrite: bool, limit: int | None) -> List[Tuple[int, str]]:
    """
    처리 대상 row 목록 가져오기.
    - overwrite=False: OUT_COL이 비어 있고 IN_COL은 존재하는 행만
    - overwrite=True : IN_COL이 있는 행은 모두(기존 값 덮어쓰기)
    - limit가 있으면 최대 limit개까지만
    """
    cur = conn.cursor()
    if overwrite:
        sql = f"""
        SELECT id, {IN_COL}
        FROM {TABLE_NAME}
        WHERE TRIM(COALESCE({IN_COL}, '')) <> ''
        """
    else:
        sql = f"""
        SELECT id, {IN_COL}
        FROM {TABLE_NAME}
        WHERE TRIM(COALESCE({OUT_COL}, '')) = ''
          AND TRIM(COALESCE({IN_COL}, '')) <> ''
        """
    if limit:
        sql += f" LIMIT {int(limit)}"
    return cur.execute(sql).fetchall()


# ------------------------------------------------------------
# Playwright를 이용한 JS 리디렉션 추적
# ------------------------------------------------------------
def resolve_with_playwright(url: str, page, wait_ms: int) -> str | None:
    """
    주어진 URL로 이동한 뒤 JS 실행을 기다렸다가,
    그 시점의 page.url을 최종 URL로 반환한다.
    - 실패하면 None 반환
    """
    if not url:
        return None
    try:
        # DOMContentLoaded까지 기다린 뒤, JS 리디렉션을 위해 추가 wait_ms 대기
        page.goto(url, wait_until="domcontentloaded", timeout=15000)
        page.wait_for_timeout(wait_ms)
        return page.url
    except Exception:
        return None


# ------------------------------------------------------------
# 메인 로직
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="JS 기반 리디렉션(브라우저 레벨)으로 최종 URL을 script_redirect_url2에 저장"
    )
    parser.add_argument("--db", default=DB_PATH, help="SQLite DB 경로")
    parser.add_argument("--table", default=TABLE_NAME, help="테이블 이름 (기본: adult_dedup)")
    parser.add_argument("--overwrite", action="store_true", help="기존 script_redirect_url2 값이 있어도 덮어쓰기")
    parser.add_argument("--wait-ms", type=int, default=1000, help="JS 리디렉션 대기 시간(ms 단위, 기본 1000)")
    parser.add_argument("--limit", type=int, default=None, help="최대 처리 row 수 (디버깅용)")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    verify_table(conn, args.table)

    rows = fetch_rows(conn, args.overwrite, args.limit)
    total = len(rows)
    if not rows:
        print("[i] 처리할 row가 없습니다.")
        return

    print(f"[i] DB: {args.db}")
    print(f"[i] Table: {args.table}")
    print(f"[i] 대상 row 수: {total} (overwrite={args.overwrite}, wait_ms={args.wait_ms})")

    ok_cnt, err_cnt = 0, 0

    # Playwright 시작
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            )
        )
        page = context.new_page()

        # tqdm 막대기: 화면 맨 아래 하나만 유지
        bar = tqdm(total=total, desc="JS redirect resolve")

        for row_id, src_url in rows:
            final_url = resolve_with_playwright(src_url, page, args.wait_ms)

            if final_url and isinstance(final_url, str):
                ok_cnt += 1
                conn.execute(
                    f"UPDATE {args.table} SET {OUT_COL} = ? WHERE id = ?",
                    (final_url, row_id),
                )
                conn.commit()
                tqdm.write(f"[OK]  id={row_id} | {src_url}  ->  {final_url}")

            else:
                err_cnt += 1
                tqdm.write(f"[ERR] id={row_id} | {src_url}  ->  (JS redirect 감지 실패)")

                # 🔥 실패 기록 저장!
                conn.execute(
                    f"UPDATE {args.table} SET {OUT_COL} = ? WHERE id = ?",
                    ("ERR: (JS redirect 감지 실패)", row_id),
                )
                conn.commit()

            bar.update(1)
            bar.set_postfix(ok=ok_cnt, err=err_cnt)


        bar.close()
        browser.close()
        conn.close()

    print(f"\n[결과] 총 {total}건 중 성공 {ok_cnt}건, 실패 {err_cnt}건")


if __name__ == "__main__":
    main()
