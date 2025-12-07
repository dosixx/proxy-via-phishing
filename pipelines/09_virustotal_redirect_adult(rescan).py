import time
import base64
import requests
from tqdm import tqdm
from datetime import datetime
import psycopg2
import logging

# ==========================================
# [설정] - 실제 사용되는 설정입니다.
# ==========================================

DAILY_LIMIT = 340 #일일 할당량
TABLE_NAME = "redirect_2plus_final_split"
PRIMARY_KEY_COL = "original_rowid"
VT_FREE_SLEEP_SEC = 16 
MAX_GET_ATTEMPTS = 3 
ANALYSIS_WAIT_SEC = 60 

# 컬럼명 맵핑: (신규 컬럼명, 데이터 타입)
RESCAN_COLUMNS = [
    ("re_vt_scan_date", "TEXT"),
    ("re_vt_malicious_count", "INTEGER"),
    ("re_vt_details", "TEXT"),
    ("re_vt_max_malicious_score", "INTEGER"),
    ("re_vt_http_code", "TEXT"),
    ("re_vt_reputation", "INTEGER"),
    ("re_vt_suspicious_count", "INTEGER"),
    ("re_vt_timeout_count", "INTEGER"),
]

# ==========================================
# [유틸리티 함수] - 중복 제거 및 최종 사용 버전
# ==========================================

def get_db_connection():
    # DB_DSN을 사용하여 실제 연결을 생성합니다.
    return psycopg2.connect(DB_DSN)

def init_db_columns(conn):
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s
        """,
        (TABLE_NAME,),
    )
    existing = {row[0] for row in cur.fetchall()}

    for col_name, col_type in RESCAN_COLUMNS:
        if col_name not in existing:
            cur.execute(
                f"ALTER TABLE {TABLE_NAME} "
                f"ADD COLUMN IF NOT EXISTS {col_name} {col_type}"
            )

    conn.commit()
    cur.close()

def encode_url_for_vt(url: str) -> str:
    # URL을 Base64로 인코딩합니다.
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def is_valid_url(url: str) -> bool:
    # URL 유효성을 확인합니다.
    url_lower = url.lower().strip()
    return url_lower.startswith("http://") or url_lower.startswith("https://")

def update_db_status(cur, pk, status_code, details, result_data=None):
    # DB에 스캔 결과 및 상태를 업데이트합니다.
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 기본값 설정
    malicious_count = result_data.get('malicious', 0) if result_data else 0
    max_score = result_data.get('malicious', 0) if result_data else 0 # 재스캔에서는 malicious_count를 max_malicious_score로 사용
    reputation = result_data.get('reputation', 0) if result_data else 0
    suspicious = result_data.get('suspicious', 0) if result_data else 0
    timeout = result_data.get('timeout', 0) if result_data else 0
    
    # SQL 쿼리 구성
    cur.execute(
        f"""
        UPDATE {TABLE_NAME}
        SET re_vt_scan_date = %s,
            re_vt_http_code = %s,
            re_vt_details = %s,
            re_vt_malicious_count = %s,
            re_vt_max_malicious_score = %s,
            re_vt_reputation = %s,
            re_vt_suspicious_count = %s,
            re_vt_timeout_count = %s
        WHERE {PRIMARY_KEY_COL} = %s
        """,
        (
            current_time,
            str(status_code),
            details,
            malicious_count,
            max_score,
            reputation,
            suspicious,
            timeout,
            pk,
        ),
    )


# ==========================================
# 🚀 메인 함수 (최종 안정화 버전)
# ==========================================

def rescan_and_fetch_results():
    # 1. 초기 DB 연결 시도
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        init_db_columns(conn)
        cur = conn.cursor()
    except Exception as e:
        print(f"초기 DB 연결 실패: {e}")
        return

    try:
        # 이전에 '은닉'으로 처리되었던 대상을 가져옴
        query = f"""
            SELECT {PRIMARY_KEY_COL}, script_redirect_url
            FROM {TABLE_NAME}
            WHERE script_redirect_url IS NOT NULL
              AND vt_status_type = '은닉'
              AND re_vt_malicious_count IS NULL
            ORDER BY {PRIMARY_KEY_COL}
        """
        cur.execute(query)
        targets = cur.fetchall()
    except Exception as e:
        print(f"DB 읽기 에러: {e}")
        try:
            cur.close()
            conn.close()
        except:
            pass
        return

    print(f"재스캔 및 수집 대상: {len(targets)}개 (일일 제한 {DAILY_LIMIT}회)")
    print(f"API 요청 간 지연 시간: {VT_FREE_SLEEP_SEC}초")
    print(f"분석 대기 시간: {ANALYSIS_WAIT_SEC}초")
    print("---------------------------------------------------")

    headers = {"accept": "application/json", "x-apikey": API_KEY}
    post_api_url = "https://www.virustotal.com/api/v3/urls"
    api_calls_today = 0
    
    last_error_message = "" 

    for pk, raw_url in tqdm(targets, desc="VT Analysis", unit="url"):
        
        # 2. 루프 시작 시 DB 연결 상태 확인 및 복구 로직
        try:
            # conn.closed는 psycopg2.connection의 속성이므로, conn이 유효할 때만 시도
            if conn and conn.closed:
                raise psycopg2.InterfaceError("Connection is closed, re-establishing.")
            if cur and cur.closed:
                 raise psycopg2.InterfaceError("Cursor is closed, re-establishing.")
        except (AttributeError, psycopg2.InterfaceError):
            try:
                tqdm.write("\n[🔄 DB 재연결 시도] 이전 연결이 끊어졌습니다.")
                conn = get_db_connection()
                cur = conn.cursor()
            except Exception as e:
                tqdm.write(f"\n[🚨 치명적 재연결 실패] 스크립트를 중단합니다: {e}")
                return # 연결 자체가 불가능하면 스크립트 종료
        
        # --- 최상위 예외 처리 시작 ---
        try: 
            # 쿼터 초과 시 종료
            if api_calls_today >= DAILY_LIMIT:
                print(f"\n[종료] 쿼터({DAILY_LIMIT}) 달성.")
                break

            url = raw_url.strip()
            display_url = url[:40] + "..." if len(url) > 40 else url

            if not is_valid_url(url):
                tqdm.write(f" [🚫Skip] 유효 URL 아님 → {url[:50]}")
                continue

            # --- 1단계: POST 요청 (재분석 요청) ---
            post_success = False
            tqdm.write(f" [{pk}] 1/3 POST 요청 시작: {display_url}")
            
            payload = {"url": url}
            try:
                response = requests.post(post_api_url, headers=headers, data=payload)
                api_calls_today += 1
                
                if response.status_code == 200 or response.status_code == 202:
                    update_db_status(cur, pk, response.status_code, "POST Submitted/Accepted.", {})
                    conn.commit()
                    tqdm.write(f"   └─ [✅POST 성공 {response.status_code}] 분석 요청 완료. 대기 시작...")
                    post_success = True

                elif response.status_code == 429:
                    tqdm.write("[⛔] VirusTotal rate limit (429). 스크립트 종료.")
                    cur.close()
                    conn.close()
                    return

                else:
                    update_db_status(cur, pk, response.status_code, f"POST Failed (Code: {response.status_code}).", {})
                    conn.commit()
                    tqdm.write(f"   └─ [❌POST 실패 {response.status_code}] 요청 실패. 다음 URL로 이동.")
                    time.sleep(VT_FREE_SLEEP_SEC)
                    continue

            except Exception as e:
                update_db_status(cur, pk, 0, f"POST Exception: {e}", {})
                conn.commit()
                tqdm.write(f"   └─ [⚠️POST 예외] {e}. 다음 URL로 이동.")
                time.sleep(VT_FREE_SLEEP_SEC)
                continue
            
            # --- 2단계: 대기 ---
            if post_success:
                tqdm.write(f" [{pk}] 2/3 분석 완료 대기 중 ({ANALYSIS_WAIT_SEC}초)...")
                time.sleep(ANALYSIS_WAIT_SEC)

            # --- 3단계: GET 요청 (결과 수집) ---
            tqdm.write(f" [{pk}] 3/3 GET 요청 시작 (최대 {MAX_GET_ATTEMPTS}회 시도): {display_url}")

            url_id = encode_url_for_vt(url)
            get_api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            
            get_attempts = 0
            get_result_found = False
            last_error_message = "" 

            while get_attempts < MAX_GET_ATTEMPTS and api_calls_today < DAILY_LIMIT:
                get_attempts += 1
                time.sleep(VT_FREE_SLEEP_SEC)

                try:
                    response = requests.get(get_api_url, headers=headers)
                    api_calls_today += 1

                    if response.status_code == 200:
                        data = response.json().get("data", {}).get("attributes", {})
                        stats = data.get("last_analysis_stats", {})
                        
                        result_data = {
                            "malicious": stats.get("malicious", 0),
                            "reputation": data.get("reputation", 0),
                            "suspicious": stats.get("suspicious", 0),
                            "timeout": stats.get("timeout", 0),
                        }
                        mal_count = result_data["malicious"]
                        
                        update_db_status(cur, pk, response.status_code, f"GET Succeeded (Malicious: {mal_count}).", result_data)
                        conn.commit()

                        status_text = "🚨 악성" if mal_count > 0 else "✅ 정상"
                        tqdm.write(f"   └─ [🎉GET 성공] {status_text} (탐지: {mal_count}점) - {get_attempts}회 시도")
                        get_result_found = True
                        break

                    elif response.status_code == 204:
                        tqdm.write(f"   └─ [⏳GET 대기] 분석 미완료 (204 No Content). 잠시 후 재시도... ({get_attempts}/{MAX_GET_ATTEMPTS})")
                        if get_attempts < MAX_GET_ATTEMPTS:
                            time.sleep(ANALYSIS_WAIT_SEC)
                        continue
                    
                    elif response.status_code == 404:
                        tqdm.write(f"   └─ [👻GET 은닉 404] 재스캔 후에도 은닉(404) 상태 유지. 종료.")
                        update_db_status(cur, pk, response.status_code, "GET Failed (404 Not Found) - Remains Hidden.", {})
                        conn.commit()
                        get_result_found = True
                        break

                    elif response.status_code == 429:
                        tqdm.write("[⛔] VirusTotal rate limit (429). 스크립트 종료.")
                        cur.close()
                        conn.close()
                        return

                    else:
                        tqdm.write(f"   └─ [⚠️GET HTTP {response.status_code}] 예상치 못한 응답. 재시도... ({get_attempts}/{MAX_GET_ATTEMPTS})")
                        continue

                except Exception as e:
                    last_error_message = str(e).lower()
                    tqdm.write(f"   └─ [⚠️GET 예외] {e}. 재시도... ({get_attempts}/{MAX_GET_ATTEMPTS})")
                    
                    # 치명적 DB 오류 유발 키워드 감지
                    if "timed out" in last_error_message or "cursor already closed" in last_error_message or "ssl syscall error" in last_error_message or "can't assign requested address" in last_error_message:
                        tqdm.write(f"\n[🚨 치명적 I/O 오류 감지] 현재 DB 연결을 정리하고 다음 URL로 이동합니다.")
                        try:
                            cur.close()
                            conn.close()
                        except:
                            pass
                        
                        get_attempts = MAX_GET_ATTEMPTS 
                        get_result_found = True 
                        break 
                    elif "timed out" in last_error_message:
                        # DB 연결은 끊지 않고, 분석 완료를 위해 추가 대기 시간을 부여합니다.
                        tqdm.write(f"   └─ [⏳분석 대기] I/O 타임아웃 감지. 분석 완료를 위해 {ANALYSIS_WAIT_SEC}초 추가 대기 후 재시도.")
                        time.sleep(ANALYSIS_WAIT_SEC) # 60초 추가 대기

                    continue

            # 최대 시도 횟수를 넘겼는데도 결과를 못 찾은 경우
            if not get_result_found:
                # 치명적 오류가 아니었을 경우에만 최종 실패를 DB에 기록
                if not ("timed out" in last_error_message or "cursor already closed" in last_error_message or "ssl syscall error" in last_error_message or "can't assign requested address" in last_error_message):
                    update_db_status(cur, pk, 999, f"GET Failed - Max Attempts ({MAX_GET_ATTEMPTS}) Reached.", {})
                    conn.commit()
                    tqdm.write(f"   └─ [❌최대 시도] {MAX_GET_ATTEMPTS}회 시도 실패. 다음 URL로 이동.")
            
        except Exception as e:
            tqdm.write(f"\n[🚨 최종 DB/루프 에러] URL {pk} 처리 중 에러 발생: {e}")
            tqdm.write("DB 연결을 정리하고 스크립트를 중단합니다.")
            try:
                cur.close()
                conn.close()
            except Exception as cleanup_e:
                tqdm.write(f"DB 종료 중 추가 에러 발생: {cleanup_e}")
            return

    # 3. 모든 작업 완료 후 연결 종료
    try:
        cur.close()
        conn.close()
    except:
        pass
        
    print("\n[완료] VirusTotal 재스캔 및 결과 수집 끝.")


if __name__ == "__main__":
    rescan_and_fetch_results()
