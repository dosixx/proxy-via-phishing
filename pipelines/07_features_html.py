"""
07_features_html.py

HTML feature extractor for proxy-via-phishing.

- Reads gzipped final DOM HTML from the main pages table
- Extracts structural & phishing-related features (forms, inputs, brands, etc.)
- Stores them into a dedicated `html_features` table
- Supports:
    * Single-id mode:
        python -m pipelines.07_features_html 5478
      -> processes that id, upserts into html_features, prints summary
    * Batch mode:
        python -m pipelines.07_features_html --limit 500
      -> processes up to 500 unseen rows, upserts into html_features (no verbose print)
"""

import argparse
import gzip
import sqlite3
import sys
import textwrap
from datetime import datetime
from typing import Dict, Optional

from bs4 import BeautifulSoup

# =========================
#  CONFIG (수정 포인트)
# =========================


# sqlite DB 파일 경로
DB_PATH = "db/translate_goog_urls.db" 

# HTML이 저장된 source 테이블 이름
SOURCE_TABLE = "url_artifacts_v2"        # 예: "dynamic_html", "playwright_pages" 등으로 수정

# source 테이블에서 사용할 컬럼 이름들
ID_COLUMN = "id"                     # 기본 key
HTML_COLUMN = "final_dom_html_gzip"  # gzipped final DOM HTML이 들어있는 BLOB 컬럼
URL_COLUMN = "final_url"             # 이 row의 translate.goog URL 또는 정규화 URL

# feature를 저장할 테이블 이름
FEATURE_TABLE = "html_features"


# =========================
#  BRAND / KEYWORD 리스트
# =========================

BRAND_KEYWORDS = [
    # 영어 브랜드/서비스명
    "microsoft", "office 365", "outlook", "gmail", "google", "facebook",
    "instagram", "netflix", "paypal", "apple", "icloud", "amazon",
    "github", "dropbox", "adobe",
    # 한국 서비스
    "네이버", "카카오", "카카오톡", "토스", "쿠팡"
]

# 로그인/인증/계정 관련 키워드 (텍스트, placeholder 등에서 검사)
AUTH_KEYWORDS = [
    # login 계열
    "login", "log in", "sign in", "sign-in", "signin",
    "log on", "sign on", "로그인", "로그 온",
    # 계정/이메일
    "account", "my account", "계정", "아이디", "id",
    "email", "e-mail", "이메일",
    # 인증/검증
    "verify", "verification", "authenticate", "authentication",
    "2fa", "two-factor", "otp",
    "인증", "본인확인", "보안코드", "인증코드",
    # 비밀번호 메시지/오류
    "password", "비밀번호", "패스워드",
    "incorrect password", "invalid password", "wrong password",
    "password required", "password reset",
]

# 에러/경고 느낌의 키워드
ERROR_KEYWORDS = [
    "incorrect", "invalid", "expired", "session expired",
    "security alert", "unusual activity", "suspicious", "locked",
    "계정 잠김", "로그인 오류", "오류가 발생했습니다",
]

ADULT_KEYWORDS = [
    "adult", "xxx", "sex", "sexy", "nude", "naked", "porn",
    "pleasure", "passion", "escort", "dating", "meet women",
    "horny", "lonely girls", "hot girls", "girl"
]

GAMBLING_KEYWORDS = [
    "casino", "betting", "sportsbook", "poker", "slots",
    "roulette", "jackpot", "스포츠토토", "토토", "바카라",
]

TRANSLATE_MARKERS = [
    "translate.goog",
    "translate.googleusercontent.com",
    "google translate",
    "번역되었습니다",
]


# =========================
#  DB HELPER
# =========================

def get_connection() -> sqlite3.Connection:
    """
    sqlite3 Connection 객체를 생성한다.
    row_factory를 Row로 설정해서 dict처럼 접근 가능하게 만든다.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_feature_table(conn: sqlite3.Connection) -> None:
    """
    html_features 테이블을 생성한다 (없으면).
    page_id를 PK로 사용해서, 한 페이지당 한 row만 가지도록 설계.
    """
    cur = conn.cursor()
    cur.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {FEATURE_TABLE} (
            page_id INTEGER PRIMARY KEY,

            -- 기본 구조 정보
            num_forms INTEGER,
            num_inputs INTEGER,
            num_input_text INTEGER,
            num_input_password INTEGER,
            num_input_email INTEGER,
            num_input_like_email INTEGER,
            num_input_like_password INTEGER,
            num_buttons INTEGER,
            num_links INTEGER,
            num_iframes INTEGER,
            num_images INTEGER,

            -- 피싱/브랜드/번역 관련 플래그
            has_password_input INTEGER,      -- 0/1
            has_login_keyword INTEGER,       -- 0/1 (과거 버전 호환용, AUTH_KEYWORDS 일부)
            has_brand_keyword INTEGER,       -- 0/1
            brand_hit_count INTEGER,
            brand_hits TEXT,                 -- comma-separated list

            has_translate_marker INTEGER,    -- 0/1

            -- 텍스트/폼 관련 추가 특징
            text_length INTEGER,
            unique_form_action_count INTEGER,
            first_form_action TEXT,
            has_email_field_like INTEGER,    -- 0/1 (name/placeholder에 email 관련 토큰)
            has_password_field_like INTEGER, -- 0/1 (name/placeholder에 password 토큰)

            -- 인증/오류/성인/도박 키워드
            has_auth_keyword_text INTEGER,   -- 0/1 (페이지 텍스트)
            has_auth_keyword_form INTEGER,   -- 0/1 (input name/placeholder 쪽)
            auth_keyword_hit_count INTEGER,
            auth_keyword_hits TEXT,
            has_error_keyword INTEGER,       -- 0/1
            has_adult_keyword INTEGER,       -- 0/1
            has_gambling_keyword INTEGER,    -- 0/1

            -- iframe 출처 요약
            iframe_src_domains TEXT,         -- comma-separated hostnames (상위 몇 개만)

            created_at TEXT                  -- ISO timestamp
        )
        """
    )
    conn.commit()



# =========================
#  HTML 유틸
# =========================

def gunzip_to_str(blob) -> Optional[str]:
    """
    final_dom_html_gzip BLOB을 str로 변환.
    - gzip이면 decompress
    - gzip 아니면 그냥 UTF-8 decode
    - 실패하면 None
    """
    if blob is None:
        return None

    # sqlite가 memoryview로 줄 수 있음
    if isinstance(blob, memoryview):
        blob = blob.tobytes()

    if isinstance(blob, str):
        return blob

    if not isinstance(blob, (bytes, bytearray)):
        return None

    # 1) gzip 시도
    try:
        return gzip.decompress(blob).decode("utf-8", errors="replace")
    except Exception:
        # 2) gzip 아니면 그냥 decode
        try:
            return blob.decode("utf-8", errors="replace")
        except Exception:
            return None


def extract_html_features(html: str) -> Dict:
    """
    HTML 문자열에서 구조적/피싱/성인/인증 관련 feature를 추출한다.
    BeautifulSoup 기반의 정적 분석.
    """
    soup = BeautifulSoup(html, "html.parser")

    forms = soup.find_all("form")
    inputs = soup.find_all("input")
    buttons = soup.find_all("button")
    links = soup.find_all("a")
    iframes = soup.find_all("iframe")
    images = soup.find_all("img")

    def _input_type(el, t: str) -> bool:
        return (el.get("type") or "").lower() == t

    input_text = [i for i in inputs if _input_type(i, "text")]
    input_password = [i for i in inputs if _input_type(i, "password")]
    input_email = [i for i in inputs if _input_type(i, "email")]

    # ---- input 메타데이터 기반 like-email/password 인풋 탐지 ----
    num_input_like_email = 0
    num_input_like_password = 0

    auth_keywords_form_hits = set()

    for inp in inputs:
        type_ = (inp.get("type") or "").lower()
        name = (inp.get("name") or "").lower()
        iid = (inp.get("id") or "").lower()
        placeholder = (inp.get("placeholder") or "").lower()

        meta_all = " ".join([type_, name, iid, placeholder])

        # email field-like?
        if ("email" in meta_all) or (type_ == "email"):
            num_input_like_email += 1

        # password field-like?
        if ("password" in meta_all) or (type_ == "password") or ("비밀번호" in meta_all):
            num_input_like_password += 1

        # auth keyword hits in form fields
        for kw in AUTH_KEYWORDS:
            if kw.lower() in meta_all:
                auth_keywords_form_hits.add(kw.lower())

    has_email_field_like = int(num_input_like_email > 0)
    has_password_field_like = int(num_input_like_password > 0)

    # ---- 페이지 전체 텍스트 기반 특징 ----
    text = soup.get_text(separator=" ", strip=True)
    text_lower = text.lower()
    text_length = len(text)

    # 단순 login keyword (과거 필드 유지용. AUTH_KEYWORDS 일부만 사용해도 됨)
    simple_login_keywords = ["login", "로그인", "sign in", "signin"]
    has_login_keyword = int(any(k in text_lower for k in simple_login_keywords))

    # 인증/계정 관련 키워드 (텍스트)
    auth_keyword_text_hits = [kw.lower() for kw in AUTH_KEYWORDS if kw.lower() in text_lower]
    has_auth_keyword_text = int(len(auth_keyword_text_hits) > 0)

    # 에러/경고 키워드
    has_error_keyword = int(any(kw.lower() in text_lower for kw in ERROR_KEYWORDS))

    # 브랜드 키워드
    brand_hits = [b for b in BRAND_KEYWORDS if b.lower() in text_lower]
    brand_hit_count = len(brand_hits)
    has_brand_keyword = int(brand_hit_count > 0)
    brand_hits_str = ",".join(brand_hits[:20])

    # 성인/도박 키워드
    has_adult_keyword = int(any(kw.lower() in text_lower for kw in ADULT_KEYWORDS))
    has_gambling_keyword = int(any(kw.lower() in text_lower for kw in GAMBLING_KEYWORDS))

    # translate proxy UI marker 탐지
    has_translate_marker = int(
        any(marker.lower() in text_lower for marker in TRANSLATE_MARKERS)
    )

    # form action 분석 (단순 버전)
    form_actions = []
    for f in forms:
        action = (f.get("action") or "").strip()
        if action:
            form_actions.append(action)
    unique_form_action_count = len(set(form_actions))
    first_form_action = form_actions[0][:255] if form_actions else None

    # iframe src에서 hostname만 추출해서 상위 몇 개 기록
    iframe_hosts = []
    for fr in iframes:
        src = (fr.get("src") or "").strip()
        if not src:
            continue
        try:
            host = urlparse(src).hostname or ""
        except Exception:
            host = ""
        host = host.lower()
        if host:
            iframe_hosts.append(host)

    # 너무 많으면 상위 10개만
    iframe_hosts = list(dict.fromkeys(iframe_hosts))  # unique preserving order
    iframe_src_domains_str = ",".join(iframe_hosts[:10])

    # auth keywords (폼 + 텍스트) 합치기
    all_auth_hits = set(auth_keyword_text_hits) | auth_keywords_form_hits
    auth_keyword_hit_count = len(all_auth_hits)
    auth_keyword_hits_str = ",".join(sorted(list(all_auth_hits))[:20])

    features = {
        "num_forms": len(forms),
        "num_inputs": len(inputs),
        "num_input_text": len(input_text),
        "num_input_password": len(input_password),
        "num_input_email": len(input_email),
        "num_input_like_email": num_input_like_email,
        "num_input_like_password": num_input_like_password,
        "num_buttons": len(buttons),
        "num_links": len(links),
        "num_iframes": len(iframes),
        "num_images": len(images),

        "has_password_input": int(len(input_password) > 0),
        "has_login_keyword": has_login_keyword,
        "has_brand_keyword": has_brand_keyword,
        "brand_hit_count": brand_hit_count,
        "brand_hits": brand_hits_str,

        "has_translate_marker": has_translate_marker,
        "text_length": text_length,
        "unique_form_action_count": unique_form_action_count,
        "first_form_action": first_form_action,

        "has_email_field_like": has_email_field_like,
        "has_password_field_like": has_password_field_like,

        "has_auth_keyword_text": has_auth_keyword_text,
        "has_auth_keyword_form": int(len(auth_keywords_form_hits) > 0),
        "auth_keyword_hit_count": auth_keyword_hit_count,
        "auth_keyword_hits": auth_keyword_hits_str,

        "has_error_keyword": has_error_keyword,
        "has_adult_keyword": has_adult_keyword,
        "has_gambling_keyword": has_gambling_keyword,

        "iframe_src_domains": iframe_src_domains_str,
    }

    return features



# =========================
#  DB I/O: select & upsert
# =========================

def fetch_page_by_id(conn: sqlite3.Connection, page_id: int) -> Optional[sqlite3.Row]:
    """
    특정 id에 해당하는 source row를 가져온다.
    - id, gzipped html, url만 추출
    """
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT
            {ID_COLUMN} AS id,
            {HTML_COLUMN} AS html_gz,
            {URL_COLUMN} AS url
        FROM {SOURCE_TABLE}
        WHERE {ID_COLUMN} = ?
        """,
        (page_id,),
    )
    return cur.fetchone()


def fetch_unprocessed_pages(conn: sqlite3.Connection, limit: int):
    """
    html_features에 아직 없는 source row를 최대 limit개까지 가져온다.
    LEFT JOIN으로 아직 feature 없는 row만 뽑는다.
    """
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT
            s.{ID_COLUMN} AS id,
            s.{HTML_COLUMN} AS html_gz,
            s.{URL_COLUMN} AS url
        FROM {SOURCE_TABLE} AS s
        LEFT JOIN {FEATURE_TABLE} AS h
          ON h.page_id = s.{ID_COLUMN}
        WHERE h.page_id IS NULL
        ORDER BY s.{ID_COLUMN} ASC
        LIMIT ?
        """,
        (limit,),
    )
    return cur.fetchall()


def upsert_html_features(conn: sqlite3.Connection, page_id: int, features: Dict) -> None:
    """
    html_features 테이블에 feature를 INSERT OR REPLACE 한다.
    같은 page_id가 이미 있으면 덮어쓴다.
    """
    cur = conn.cursor()
    created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    cur.execute(
        f"""
        INSERT OR REPLACE INTO {FEATURE_TABLE} (
            page_id,
            num_forms,
            num_inputs,
            num_input_text,
            num_input_password,
            num_input_email,
            num_input_like_email,
            num_input_like_password,
            num_buttons,
            num_links,
            num_iframes,
            num_images,
            has_password_input,
            has_login_keyword,
            has_brand_keyword,
            brand_hit_count,
            brand_hits,
            has_translate_marker,
            text_length,
            unique_form_action_count,
            first_form_action,
            has_email_field_like,
            has_password_field_like,
            has_auth_keyword_text,
            has_auth_keyword_form,
            auth_keyword_hit_count,
            auth_keyword_hits,
            has_error_keyword,
            has_adult_keyword,
            has_gambling_keyword,
            iframe_src_domains,
            created_at
        ) VALUES (
            :page_id,
            :num_forms,
            :num_inputs,
            :num_input_text,
            :num_input_password,
            :num_input_email,
            :num_input_like_email,
            :num_input_like_password,
            :num_buttons,
            :num_links,
            :num_iframes,
            :num_images,
            :has_password_input,
            :has_login_keyword,
            :has_brand_keyword,
            :brand_hit_count,
            :brand_hits,
            :has_translate_marker,
            :text_length,
            :unique_form_action_count,
            :first_form_action,
            :has_email_field_like,
            :has_password_field_like,
            :has_auth_keyword_text,
            :has_auth_keyword_form,
            :auth_keyword_hit_count,
            :auth_keyword_hits,
            :has_error_keyword,
            :has_adult_keyword,
            :has_gambling_keyword,
            :iframe_src_domains,
            :created_at
        )
        """,
        {
            "page_id": page_id,
            **features,
            "created_at": created_at,
        },
    )



# =========================
#  출력용 helper (단일 id)
# =========================

def print_page_summary(page_row: sqlite3.Row, html: str, features: Dict) -> None:
    """
    단일 id 모드에서 터미널에 보여줄 요약 출력.
    너무 많이 찍지 말고, 분석에 중요한 정보 위주로 정리.
    """
    url = page_row["url"]
    page_id = page_row["id"]

    # 텍스트 일부만 보여주기
    text = BeautifulSoup(html, "lxml").get_text(separator=" ", strip=True)
    snippet = text[:400] + ("..." if len(text) > 400 else "")

    print("=" * 80)
    print(f"[HTML FEATURES] page_id={page_id}")
    print(f"URL: {url}")
    print("-" * 80)
    
    print(f"Forms: {features['num_forms']}  "
          f"Inputs: {features['num_inputs']}  "
          f"Password inputs: {features['num_input_password']}")
    print(f"Input-like email: {features['num_input_like_email']}  "
          f"Input-like password: {features['num_input_like_password']}")
    print(f"Buttons: {features['num_buttons']}  "
          f"Links: {features['num_links']}  "
          f"Iframes: {features['num_iframes']}  "
          f"Images: {features['num_images']}")
    print(f"Text length: {features['text_length']}")
    print(f"Has password input: {bool(features['has_password_input'])}")
    print(f"Has email field-like: {bool(features['has_email_field_like'])}")
    print(f"Has login keyword(simple): {bool(features['has_login_keyword'])}")
    print(f"Has auth keyword (text/form): "
          f"{bool(features['has_auth_keyword_text'])} / "
          f"{bool(features['has_auth_keyword_form'])}")
    print(f"Auth keyword hits: {features['auth_keyword_hits']}")
    print(f"Has brand keyword: {bool(features['has_brand_keyword'])} "
          f"(count={features['brand_hit_count']}, hits={features['brand_hits']})")
    print(f"Has error keyword: {bool(features['has_error_keyword'])}")
    print(f"Has adult keyword: {bool(features['has_adult_keyword'])}")
    print(f"Has gambling keyword: {bool(features['has_gambling_keyword'])}")
    print(f"Has translate marker: {bool(features['has_translate_marker'])}")
    print(f"Unique form actions: {features['unique_form_action_count']}")
    print(f"First form action: {features['first_form_action']}")
    print(f"Iframe src domains: {features['iframe_src_domains']}")

    print("-" * 80)
    print("Text snippet:")
    print(textwrap.fill(snippet, width=78))
    print("=" * 80)


# =========================
#  MAIN
# =========================

def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        description="Extract HTML structural/phishing features into html_features table."
    )
    parser.add_argument(
        "page_id",
        nargs="?",
        type=int,
        help="Single page id to process (prints summary).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Number of unprocessed pages to process in batch mode.",
    )

    args = parser.parse_args(argv)

    if args.page_id is not None and args.limit is not None:
        parser.error("You cannot specify both a page_id and --limit.")

    conn = get_connection()
    init_feature_table(conn)

    # 단일 id 모드
    if args.page_id is not None:
        row = fetch_page_by_id(conn, args.page_id)
        if row is None:
            print(f"[!] No row found in {SOURCE_TABLE} with {ID_COLUMN}={args.page_id}")
            sys.exit(1)

        html = gunzip_to_str(row["html_gz"])
        if not html:
            print(f"[!] Could not decode HTML for id={args.page_id}")
            sys.exit(1)

        features = extract_html_features(html)
        upsert_html_features(conn, row["id"], features)
        conn.commit()

        print_page_summary(row, html, features)
        return

    # 배치 모드
    limit = args.limit if args.limit is not None else 1000
    rows = fetch_unprocessed_pages(conn, limit)

    if not rows:
        print(f"[+] No unprocessed rows found in {SOURCE_TABLE}.")
        return

    processed = 0
    for row in rows:
        html = gunzip_to_str(row["html_gz"])
        if not html:
            # HTML 디코딩 실패하면 스킵
            continue
        features = extract_html_features(html)
        upsert_html_features(conn, row["id"], features)
        processed += 1

    conn.commit()
    print(f"[+] Processed {processed} rows (limit={limit}) into {FEATURE_TABLE}.")


if __name__ == "__main__":
    main()
