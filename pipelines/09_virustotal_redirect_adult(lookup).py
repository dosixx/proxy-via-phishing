import time
import base64
import requests
from tqdm import tqdm
from datetime import datetime
import psycopg2

# ==========================================
# [설정]
#API_KEY = "d0deb3e8567a21688ccb1706782858fc0aebf3ece5c6a84f731e94c9541d5e1e" #dosix
#API_KEY = "97859e5b22dafb300803235c6b6dad0eef6d416a2d7112f11a8c200ccb9beb91" #kimdoyeon
API_KEY = "27e6cdfa30eddb16f55a858a2e1ec783c9067ada412b5bb1bdf099f69f7f9ac2" #효은
DAILY_LIMIT = 495 #일일 할당량 (500 - 여유분 5)

# PostgreSQL DSN (Neon에서 복사해온 문자열 사용)
# 실제 값 예시:
# "postgresql://neondb_owner:비번@ep-...us-east-1.aws.neon.tech/translate_goog_urls?sslmode=require&channel_binding=require"
#DB_DSN = "postgresql://neondb_owner:YOURPASS@YOURHOST/translate_goog_urls?sslmode=require&channel_binding=require"
DB_DSN ="postgresql://neondb_owner:npg_gZeSkoB7h5LV@ep-steep-wind-a4xmp84x-pooler.us-east-1.aws.neon.tech/translate_goog_urls?sslmode=require&channel_binding=require"
TABLE_NAME = "adult_redirect_v1"
PRIMARY_KEY_COL = "original_rowid"   # ← 너 테이블 PK 컬럼 이름으로 바꿔줘 (예: "id", "original_rowid" 등)
# ==========================================


def get_db_connection():
    # DSN 문자열 하나만 넣어줘도 psycopg2가 알아서 파싱함
    return psycopg2.connect(DB_DSN)


def init_db_columns(conn):
    cur = conn.cursor()

    columns_to_add = [
        ("vt_latest_date", "TEXT"),
        ("vt_max_malicious_score", "INTEGER"),
        ("vt_last_submission_date", "TEXT"),
        ("vt_times_submitted", "INTEGER"),
        ("vt_http_code", "TEXT"),
    ]

    # PostgreSQL에서 현재 테이블 컬럼 목록 조회
    cur.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        """,
        (TABLE_NAME,),
    )
    existing = {row[0] for row in cur.fetchall()}

    for col_name, col_type in columns_to_add:
        if col_name not in existing:
            # Postgres는 IF NOT EXISTS 지원
            cur.execute(
                f"ALTER TABLE {TABLE_NAME} "
                f"ADD COLUMN IF NOT EXISTS {col_name} {col_type}"
            )

    conn.commit()
    cur.close()


def encode_url_for_vt(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def ts_to_date(ts):
    if ts:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
    return None


def is_valid_url(url: str) -> bool:
    url_lower = url.lower().strip()
    return url_lower.startswith("http://") or url_lower.startswith("https://")


def scan_targets():
    conn = get_db_connection()
    init_db_columns(conn)
    cur = conn.cursor()

    try:
        # 아직 VT 안 돌린 행만 가져오기
        query = f"""
            SELECT {PRIMARY_KEY_COL}, second_page_url, script_redirect_url
            FROM {TABLE_NAME}
            WHERE vt_redirect_scan_date IS NULL
        """
        cur.execute(query)
        targets = cur.fetchall()
    except Exception as e:
        print(f"DB 읽기 에러: {e}")
        cur.close()
        conn.close()
        return

    print(f"대기열: {len(targets)}개 (일일 제한 {DAILY_LIMIT}회)")
    print("---------------------------------------------------")

    headers = {"accept": "application/json", "x-apikey": API_KEY}
    api_calls_today = 0

    for pk, entry_url, raw_url in tqdm(targets, desc="Smart Filter Scan", unit="url"):
        if api_calls_today >= DAILY_LIMIT:
            print(f"\n[종료] 쿼터({DAILY_LIMIT}) 달성.")
            break

        if not raw_url:
            continue

        list_details = []
        list_first_dates = []
        list_last_dates = []
        list_tags = []
        list_titles = []
        list_engines = []
        list_http = []
        comp_dates = []
        comp_scores = []
        sum_times_submitted = 0

        # redirect_url은 1개라고 가정
        url = raw_url.strip()

        if not is_valid_url(url):
            # 노이즈로 분류해서 VT 안 돌리고 바로 Excluded 처리
            short_noise = url[:30] + "..." if len(url) > 30 else url
            list_details.append(f"[노이즈/제외]{short_noise}")

            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            str_details = " || ".join(list_details)

            cur.execute(
                f"""
                UPDATE {TABLE_NAME}
                SET vt_redirect_scan_date = %s,
                    vt_redirect_malicious_count = 0,
                    vt_redirect_not_found_count = 0,
                    vt_redirect_total_scanned = 0,
                    vt_redirect_details = %s,
                    vt_latest_date = 'Excluded',
                    vt_max_malicious_score = 0
                WHERE {PRIMARY_KEY_COL} = %s
                """,
                (current_time, str_details, pk),
            )
            conn.commit()
            tqdm.write(f" [🚫Skip] 유효 URL 아님 → {short_noise}")
            continue

        # 여기부터는 실제로 VT 돌리는 케이스
        malicious_sum = 0
        not_found_sum = 0
        display_url = url[:40] + "..." if len(url) > 40 else url

        vt_id = encode_url_for_vt(url)
        api_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"

        try:
            response = requests.get(api_url, headers=headers)
            api_calls_today += 1

            if response.status_code == 200:
                data = response.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})

                mal = stats.get("malicious", 0)
                malicious_sum = 1 if mal > 0 else 0
                comp_scores.append(mal)

                ts1 = data.get("first_submission_date", 0)
                ts2 = data.get("last_submission_date", 0)
                d1 = ts_to_date(ts1)
                d2 = ts_to_date(ts2)

                if d1:
                    list_first_dates.append(d1)
                    comp_dates.append(d1)
                else:
                    list_first_dates.append("Unknown")
                if d2:
                    list_last_dates.append(d2)

                list_tags.extend(data.get("tags", []))
                if data.get("title"):
                    list_titles.append(data.get("title")[:20])

                sum_times_submitted += data.get("times_submitted", 0)
                list_http.append(str(data.get("last_http_response_code", "")))

                if mal > 0:
                    results = data.get("last_analysis_results", {})
                    for eng, res in results.items():
                        if res["category"] == "malicious":
                            list_engines.append(eng)

                    list_details.append(f"[{mal}악성]{url}")
                    tqdm.write(f"   └─ [🚨악성 {mal}] {display_url} (최초: {d1})")
                else:
                    list_details.append(f"[정상]{url}")
                    tqdm.write(f"   └─ [✅정상] {display_url}")

            elif response.status_code == 404:
                not_found_sum = 1
                comp_scores.append(0)
                list_first_dates.append("New/Hidden")
                list_details.append(f"[은닉]{url}")
                list_http.append("404")
                tqdm.write(f"   └─ [👻은닉] {display_url} (기록 없음!)")

            elif response.status_code == 429:
                tqdm.write("[⛔] VirusTotal rate limit (429). 스크립트 종료.")
                cur.close()
                conn.close()
                return

            else:
                list_details.append(f"[HTTP{response.status_code}]{url}")
                tqdm.write(f"   └─ [⚠️HTTP {response.status_code}] {display_url}")

        except Exception as e:
            list_details.append(f"[에러]{url}")
            tqdm.write(f"   └─ [⚠️에러] {e}")

        # VT 무료 API 속도 제한 맞추기
        time.sleep(15)

        # --- DB 업데이트 ---
        latest_date = max(comp_dates) if comp_dates else ""
        max_score = max(comp_scores) if comp_scores else 0

        str_first_dates = ", ".join(list_first_dates)
        str_tags = ", ".join(list(set(list_tags)))
        str_titles = " | ".join(list_titles)
        str_engines = ", ".join(list(set(list_engines)))
        str_details = " || ".join(list_details)
        str_last_dates = ", ".join(list_last_dates)
        str_http = ", ".join(list_http)

        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cur.execute(
            f"""
            UPDATE {TABLE_NAME}
            SET vt_redirect_scan_date = %s,
                vt_redirect_malicious_count = %s,
                vt_redirect_not_found_count = %s,
                vt_redirect_total_scanned = %s,
                vt_redirect_details = %s,
                vt_first_seen_date = %s,
                vt_tags = %s,
                vt_page_title = %s,
                vt_detected_engines = %s,
                vt_latest_date = %s,
                vt_max_malicious_score = %s,
                vt_last_submission_date = %s,
                vt_times_submitted = %s,
                vt_http_code = %s
            WHERE {PRIMARY_KEY_COL} = %s
            """,
            (
                current_time,
                malicious_sum,
                not_found_sum,
                1,  # redirect_url 1개 가정
                str_details,
                str_first_dates,
                str_tags,
                str_titles,
                str_engines,
                latest_date,
                max_score,
                str_last_dates,
                sum_times_submitted,
                str_http,
                pk,
            ),
        )
        conn.commit()

    cur.close()
    conn.close()
    print("\n[완료] 데이터 수집 끝.")


if __name__ == "__main__":
    scan_targets()
