from flask import Flask, request, jsonify
import requests, json, time, threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser
from byte import Encrypt_ID, encrypt_api
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from google.protobuf.json_format import MessageToDict
import os, json, threading, requests
from concurrent.futures import ThreadPoolExecutor
import AccountPersonalShow_pb2

app = Flask(__name__)

key = b"Yg&tc%DEuh6%Zc^8"
iv = b"6oyZDr22E3ychjM%"

all_tokens = []
token_status = {"is_getting": False, "count": 0, "total": 0, "success": 0}

UID = "4809817266"      
PASS = "deka_DEKA_8JZA1TY1"  
fixed_checker_token = None 

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        if result.field not in result_dict:
            result_dict[result.field] = []
        field_data = {}
        if result.wire_type in ["varint", "string", "bytes"]:
            field_data = result.data
        elif result.wire_type == "length_delimited":
            field_data = parse_results(result.data.results)
        result_dict[result.field].append(field_data)
    return {key: value[0] if len(value) == 1 else value for key, value in result_dict.items()}

def protobuf_dec(hex_str):
    try:
        return json.loads(json.dumps(parse_results(Parser().parse(hex_str)), ensure_ascii=False))
    except:
        return {}

def encrypt_api_ff(hex_data):
    try:
        plain_text = bytes.fromhex(hex_data)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
        return cipher_text.hex()
    except:
        return ""

def update_token_to_system(uid, pwd, emu=False):
    global fixed_checker_token
    try:
        from GET.token import FreeFireAPI
        data = FreeFireAPI().get(f"{uid}:{pwd}", emu)
        tk, rg = data.get("UserAuthToken"), data.get("LockRegion", "VN")
        if tk:
            with threading.Lock():
                all_tokens.insert(0, (rg, tk))
                token_status["success"] += 1
                if len(all_tokens) > 500: all_tokens.pop()
            print(f"✅ {uid}: [SUCCESS]")
            return data
    except: print(f"❌ {uid}: Lỗi")
    return None

def get_jwt_tokens():
    global fixed_checker_token
    print(f"🔄 Get Info: {UID}...")
    chk = update_token_to_system(UID, PASS)
    if chk: fixed_checker_token = chk.get("UserAuthToken")
    if not os.path.exists("accounts.json"): return
    accs = json.load(open("accounts.json", "r"))   
    token_status.update({"is_getting": True, "count": 0, "total": len(accs), "success": 0})   
    with ThreadPoolExecutor(20) as exe:
        for u, p in accs.items():
            if u != UID:
                exe.submit(update_token_to_system, u, p)
                token_status["count"] += 1

    token_status["is_getting"] = False
    print(f"\n🎯 Xong {len(all_tokens)} token.\n")

def run_get_token_periodically():
    while True:
        get_jwt_tokens()
        token_status["next_run"] = time.time() + 18000 
        time.sleep(18000)

session = requests.Session()
retry_strategy = Retry(total=2, backoff_factor=0.1, status_forcelist=[429, 500, 502, 503, 504])
adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=retry_strategy)
session.mount("https://", adapter)

def send_visit_request(uid, token, results_lock, results):
    try:
        encrypted_id = Encrypt_ID(uid)
        payload = f"08{encrypted_id}10" + "01"
        encrypted_payload = encrypt_api_ff(payload)
        
        headers = {
            "Authorization": f"Bearer {token}",
            "ReleaseVersion": "OB53",
            "X-GA": "v1 1",
            "Connection": "keep-alive"
        }
        res = session.post(
            "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow", 
            headers=headers, 
            data=bytes.fromhex(encrypted_payload), 
            timeout=3
        )
        with results_lock:
            if res.status_code == 200:
                results["thanhcong"] += 1
            else:
                results["thatbai"] += 1
    except:
        with results_lock:
            results["thatbai"] += 1

def get_account_info_protobuf(uid, token):
    try:
        encrypted_id = Encrypt_ID(uid)
        payload = f"08{encrypted_id}10" + "01"
        encrypted = encrypt_api_ff(payload)
        url = "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
        headers = {
            "Authorization": f"Bearer {token}",
            "ReleaseVersion": "OB53",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1"
        }
        res = session.post(url, headers=headers, data=bytes.fromhex(encrypted), timeout=5)
        if res.status_code != 200:
            return None
        pb = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        pb.ParseFromString(res.content)
        data = MessageToDict(pb, preserving_proto_field_name=True)
        return data
    except Exception as e:
        print("Get info error:", e)
    return None
    
@app.route("/info", methods=["GET"])
def info():
    uid = request.args.get("uid")
    if not uid: return jsonify({"error": "Thiếu UID"}), 400
    tk = fixed_checker_token or (all_tokens[0][1] if all_tokens else None)
    if not tk: return jsonify({"error": "Hệ thống chưa có token"}), 500
    data = get_account_info_protobuf(uid, tk)
    if not data: return jsonify({"error": "Lỗi lấy data hoặc token die"}), 500
    data["Owners"] = [" • @status_modz •"]
    return jsonify(data)

@app.route("/visit", methods=["GET"])
def visit():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"status": "error", "reason": "Thiếu UID"}), 400
        
    if not all_tokens:
        return jsonify({"status": "error", "reason": "Chưa có token"}), 500

    start_time = time.time()
    results = {"thanhcong": 0, "thatbai": 0}
    results_lock = threading.Lock()  
    use_tokens = all_tokens[:500]
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        for _ in range(50):
            for item in use_tokens:
                if isinstance(item, (tuple, list)):
                    region, token = item
                else:
                    region, token = "VN", item
                
                executor.submit(send_visit_request, uid, token, results_lock, results)

    acc_info = None
    try:
        r = requests.get(f"http://127.0.0.1:5000/info?uid={uid}", timeout=7)
        if r.status_code == 200:
            acc_info = r.json()
    except Exception as e:
        print(f"Lỗi khi lấy info: {e}")

    basic = acc_info.get("basic_info", {}) if acc_info else {}
    end_time = time.time()
    
    return jsonify({
        "result": {
            "API_Status": {
                "speeds": f"{round(end_time - start_time, 1)}s",
                "success": True,
                "total_sent": results["thanhcong"] + results["thatbai"]
            },
            "Visit Info": {
                "Visit Successful": results["thanhcong"],
                "Visit Failed": results["thatbai"],
                "Message": f"Đã chạy xong {results['thanhcong']} lượt visit!"
            },
            "User Info": {
                "Account Level": basic.get("level", 0),
                "Account Likes": basic.get("liked", 0),
                "Account Name": basic.get("nickname", "Unknown"),
                "Account Region": basic.get("region", "VN"),
                "Account UID": basic.get("account_id", uid)
            }
        }
    })

if __name__ == "__main__":
    threading.Thread(target=run_get_token_periodically, daemon=True).start()    
    app.run(host="0.0.0.0", port=5000, debug=False)
