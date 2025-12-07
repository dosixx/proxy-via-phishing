import sqlite3
import time
import base64
import requests
import re
from tqdm import tqdm
from datetime import datetime

# ==========================================
# [설정]
DB_PATH = "db/translate_goog_urls.db"
TABLE_NAME = "redirect_2plus_final_dedup" 
DAILY_LIMIT = 330 #일일 할당량 (500 - 여유분 5)
# ==========================================

def get_db_connection():
    return sqlite3.connect(DB_PATH)

def init_db_columns(conn):
    cursor = conn.cursor()
    
    # 기존 칼럼 + 논문용 분석 칼럼
    columns_to_add = [
        ("vt_latest_date", "TEXT"),           
        ("vt_max_malicious_score", "INTEGER"), 
        ("vt_last_submission_date", "TEXT"),   
        ("vt_times_submitted", "INTEGER"),     
        ("vt_http_code", "TEXT")               
    ]

    cursor.execute(f"PRAGMA table_info({TABLE_NAME})")
    existing_columns = [info[1] for info in cursor.fetchall()]

    for col_name, col_type in columns_to_add:
        if col_name not in existing_columns:
            try:
                cursor.execute(f"ALTER TABLE {TABLE_NAME} ADD COLUMN {col_name} {col_type}")
            except: pass
    conn.commit()

def encode_url_for_vt(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

def ts_to_date(ts):
    if ts: return datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
    return None

def is_valid_url(url):
    """
    [노이즈 필터링]
    http:// 또는 https:// 로 시작하는지 확인.
    자바스크립트 코드나 상대 경로 등을 걸러냄.
    """
    url_lower = url.lower().strip()
    return url_lower.startswith("http://") or url_lower.startswith("https://")

def scan_targets():
    conn = get_db_connection()
    init_db_columns(conn)
    cursor = conn.cursor()

    try:
        # 아직 검사 안 한 것(vt_redirect_scan_date IS NULL)만 가져오기
        query = f"""
            SELECT rowid, second_page_url, script_redirect_url 
            FROM {TABLE_NAME} 
            WHERE vt_redirect_scan_date IS NULL
        """
        cursor.execute(query)
        targets = cursor.fetchall()
    except Exception as e:
        print(f"DB 읽기 에러: {e}")
        return

    print(f"대기열: {len(targets)}개 (일일 제한 {DAILY_LIMIT}회)")
    print("---------------------------------------------------")
    
    headers = {"accept": "application/json", "x-apikey": API_KEY}
    api_calls_today = 0

    for rowid, entry_url, raw_urls in tqdm(targets, desc="Smart Filter Scan", unit="grp"):
        
        # 쿼터 체크
        if api_calls_today >= DAILY_LIMIT:
            print(f"\n[종료] 쿼터({DAILY_LIMIT}) 달성.")
            break

        if not raw_urls: continue
        
        # 1. URL 분리 및 중복 제거
        all_url_list = list(set(raw_urls.split('|')))
        
        # 2. [핵심] 노이즈 필터링
        valid_urls = []
        noise_urls = []
        
        for u in all_url_list:
            if is_valid_url(u):
                valid_urls.append(u)
            else:
                noise_urls.append(u)
        
        # 3. 검사 리스트 선정 (유효한 것 중에서만 최대 3개)
        scan_list = valid_urls[:3]
        
        # 상세 로그 리스트 (노이즈는 미리 기록)
        list_details = []
        for noise in noise_urls:
            short_noise = noise[:30] + "..." if len(noise) > 30 else noise
            list_details.append(f"[노이즈/제외]{short_noise}")
            # (선택) 터미널에 노이즈라고 알려주고 싶으면 주석 해제
            # tqdm.write(f"   └─ [🗑️노이즈] {short_noise}")

        # --- CASE A: 유효한 URL이 하나도 없는 경우 (API 절약) ---
        if not scan_list:
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            str_details = " || ".join(list_details)
            
            # DB에 'Excluded' 상태로 업데이트 -> 나중에 재검사 안 하게 만듦
            cursor.execute(f"""
                UPDATE {TABLE_NAME}
                SET vt_redirect_scan_date = ?,
                    vt_redirect_malicious_count = 0,
                    vt_redirect_not_found_count = 0,
                    vt_redirect_total_scanned = 0,
                    vt_redirect_details = ?,
                    vt_latest_date = 'Excluded',
                    vt_max_malicious_score = 0
                WHERE rowid = ?
            """, (current_time, str_details, rowid))
            conn.commit()
            
            # 터미널에 스킵 알림
            tqdm.write(f" [🚫Skip] 유효 URL 없음 (노이즈 {len(noise_urls)}개 제외됨)")
            continue # 다음 그룹으로 넘어감 (API 카운트 증가 X)

        # --- CASE B: 유효한 URL이 있는 경우 (API 사용) ---
        malicious_sum = 0
        not_found_sum = 0
        
        list_first_dates = [] 
        list_last_dates = []  
        list_tags = []        
        list_titles = []      
        list_engines = []     
        list_http = []        
        
        comp_dates = [] 
        comp_scores = []
        sum_times_submitted = 0

        # 진입 URL 표시
        # short_entry = entry_url[:50] + "..." if len(entry_url) > 50 else entry_url
        # tqdm.write(f"\n[그룹 진입] {short_entry}") 

        for url in scan_list:
            if api_calls_today >= DAILY_LIMIT: break

            url_clean = url.strip()
            # 터미널 출력용 짧은 URL
            display_url = url_clean[:40] + "..." if len(url_clean) > 40 else url_clean
            
            vt_id = encode_url_for_vt(url_clean)
            api_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
            
            try:
                response = requests.get(api_url, headers=headers)
                api_calls_today += 1 
                
                if response.status_code == 200:
                    data = response.json().get('data', {}).get('attributes', {})
                    stats = data.get('last_analysis_stats', {})
                    
                    # 1. 악성 점수
                    mal = stats.get('malicious', 0)
                    malicious_sum += 1 if mal > 0 else 0
                    comp_scores.append(mal)
                    
                    if mal == 0: pass 

                    # 2. 날짜
                    ts1 = data.get('first_submission_date', 0)
                    ts2 = data.get('last_submission_date', 0)
                    d1 = ts_to_date(ts1)
                    d2 = ts_to_date(ts2)
                    
                    if d1: 
                        list_first_dates.append(d1)
                        comp_dates.append(d1)
                    else: list_first_dates.append("Unknown")
                    if d2: list_last_dates.append(d2)

                    # 3. 기타 정보
                    list_tags.extend(data.get('tags', []))
                    if data.get('title'): list_titles.append(data.get('title')[:20])
                    sum_times_submitted += data.get('times_submitted', 0)
                    list_http.append(str(data.get('last_http_response_code', '')))

                    if mal > 0:
                        results = data.get('last_analysis_results', {})
                        for eng, res in results.items():
                            if res['category'] == 'malicious':
                                list_engines.append(eng)

                        list_details.append(f"[{mal}악성]{url_clean}")
                        
                        # [터미널 출력] 악성 발견 시 빨간맛
                        tqdm.write(f"   └─ [🚨악성 {mal}] {display_url} (최초: {d1})")
                        
                    else:
                        list_details.append(f"[정상]{url_clean}")
                        # [터미널 출력] 정상이면 조용히 (또는 체크표시)
                        tqdm.write(f"   └─ [✅정상] {display_url}")

                elif response.status_code == 404:
                    not_found_sum += 1
                    comp_scores.append(0)
                    list_first_dates.append("New/Hidden") 
                    list_details.append(f"[은닉]{url_clean}")
                    list_http.append("404")
                    
                    # [터미널 출력] 은닉 발견 시 유령 이모지
                    tqdm.write(f"   └─ [👻은닉] {display_url} (기록 없음!)")
                
                elif response.status_code == 429:
                    conn.close()
                    return

            except Exception as e:
                list_details.append(f"[에러]{url_clean}")
                tqdm.write(f"   └─ [⚠️에러] {e}")
            
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

        cursor.execute(f"""
            UPDATE {TABLE_NAME}
            SET vt_redirect_scan_date = ?,
                vt_redirect_malicious_count = ?,
                vt_redirect_not_found_count = ?,
                vt_redirect_total_scanned = ?,
                vt_redirect_details = ?,
                vt_first_seen_date = ?,
                vt_tags = ?,
                vt_page_title = ?,
                vt_detected_engines = ?,
                vt_latest_date = ?,
                vt_max_malicious_score = ?,
                vt_last_submission_date = ?,
                vt_times_submitted = ?,
                vt_http_code = ?
            WHERE rowid = ?
        """, (current_time, malicious_sum, not_found_sum, len(scan_list), str_details,
              str_first_dates, str_tags, str_titles, str_engines,
              latest_date, max_score, str_last_dates, sum_times_submitted, str_http, rowid))
        
        conn.commit()

    conn.close()
    print("\n[완료] 데이터 수집 끝.")

if __name__ == "__main__":
    scan_targets()
