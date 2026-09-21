import os
import requests
import binascii
import jwt
import base64
import urllib3
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app, origins=["*"])   # ✅ CORS ENABLED — browser se call allow

FREEFIRE_VERSION = "OB55"
DEFAULT_REGION = "IND"


# ==================== MANUAL PROTOBUF BUILDER ====================

def _encode_varint(value: int) -> bytes:
    buf = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            buf.append(b | 0x80)
        else:
            buf.append(b)
            break
    return bytes(buf)


def build_bio_protobuf(bio_text: str) -> bytes:
    out = bytearray()
    out += b'\x10\x11'
    out += b'\x2a\x00'
    out += b'\x32\x00'
    bio_bytes = bio_text.encode('utf-8')
    out += b'\x42' + _encode_varint(len(bio_bytes)) + bio_bytes
    out += b'\x48\x01'
    out += b'\x5a\x00'
    out += b'\x62\x00'
    return bytes(out)


# ==================== AES CONSTANTS ====================

AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])


def encrypt_data(data_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(data_bytes, AES.block_size)
    return cipher.encrypt(padded)


# ==================== JWT FROM UID/PASSWORD ====================

def get_jwt_from_uid_password_api(uid, password):
    url = f"https://ff-jwt-gen-api.lovable.app/api/public/token?uid={uid}&password={password}"
    try:
        print(f"[UID/PASS] Calling JWT API: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        print(f"[UID/PASS] API Response: {data}")

        if "token" in data:
            jwt_token = data["token"]
            try:
                decoded = jwt.decode(jwt_token, options={"verify_signature": False})
                account_id = str(decoded.get("account_id"))
                nickname = decoded.get("nickname", "Unknown")
                region = decoded.get("lock_region") or decoded.get("region") or DEFAULT_REGION
                print(f"[UID/PASS] Success! UID: {account_id}, Region: {region}")
                return jwt_token, account_id, nickname, region
            except Exception as e:
                print(f"[UID/PASS] JWT decode error: {e}")
                return jwt_token, uid, "Unknown", DEFAULT_REGION
        else:
            error_msg = data.get("error", "No token in response")
            print(f"[UID/PASS] API Error: {error_msg}")
            return None, None, None, None
    except Exception as e:
        print(f"[UID/PASS] Request error: {e}")
        return None, None, None, None


# ==================== ACCESS TOKEN -> JWT ====================

def get_jwt_from_access_token(access_token):
    url = f"https://ff-jwt-gen-api.lovable.app/api/public/token?access_token={access_token}"
    try:
        print(f"[Access Token] Calling JWT API...")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data.get("success") and data.get("token"):
            jwt_token = data["token"]
            account_uid = str(data.get("account_uid", ""))
            region = data.get("region", DEFAULT_REGION)
            print(f"[Access Token] Success! UID: {account_uid}, Region: {region}")
            return jwt_token, account_uid, "Unknown", region
        else:
            error_msg = data.get("error", "No token in response")
            print(f"[Access Token] API Error: {error_msg}")
            return None, None, None, None
    except Exception as e:
        print(f"[Access Token] Request error: {e}")
        return None, None, None, None


# ==================== REGION CONFIG ====================

REGION_ALIASES = {
    "EUROPE": "ME", "MIDDLEEAST": "ME", "DUBAI": "ME", "UAE": "ME",
    "SAUDI": "ME", "EGYPT": "ME", "TURKEY": "ME", "PAKISTAN": "ME", "PK": "ME",
    "ASIA": "SG", "SOUTHAMERICA": "BR", "NORTH_AMERICA": "NA"
}

REGION_MAP = {
    "IND": {"update_url": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo"},
    "ME":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "BD":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "PK":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "TW":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "TH":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "VN":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "ID":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "RU":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "EU":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "SG":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo"},
    "BR":  {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo"},
    "SAC": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo"},
    "NA":  {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo"},
}

BIO_HEADERS = {
    "Expect": "100-continue",
    "X-Unity-Version": "2018.4.12f1",
    "X-GA": "v1 1",
    "ReleaseVersion": FREEFIRE_VERSION,
    "Version": "1.132.1",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
    "Connection": "Keep-Alive",
    "Accept-Encoding": "gzip",
}


def decode_jwt_full(token):
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        return {
            "uid": str(decoded.get("account_id")),
            "name": decoded.get("nickname", "Unknown"),
            "region": (decoded.get("lock_region") or decoded.get("region") or "").upper(),
            "country": decoded.get("country_code")
        }
    except Exception:
        return None


def map_region(jwt_region):
    if not jwt_region:
        return DEFAULT_REGION
    jwt_region = jwt_region.upper()
    if jwt_region in REGION_MAP:
        return jwt_region
    if jwt_region in REGION_ALIASES:
        return REGION_ALIASES[jwt_region]
    return DEFAULT_REGION


def _add_region_param(url, region):
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q["region"] = region
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, urlencode(q), parts.fragment))


def get_region_urls(region):
    region = region.upper() if region else DEFAULT_REGION
    if region not in REGION_MAP:
        region = DEFAULT_REGION
    update_url = _add_region_param(REGION_MAP[region]["update_url"], region)
    return region, update_url


def upload_bio_request(jwt_token, bio_text, update_url):
    try:
        data_bytes = build_bio_protobuf(bio_text)
        encrypted = encrypt_data(data_bytes)

        headers = BIO_HEADERS.copy()
        headers["Authorization"] = f"Bearer {jwt_token}"

        resp = requests.post(update_url, headers=headers, data=encrypted, verify=False)

        status_text = "Unknown"
        if resp.status_code == 200:
            status_text = "Success"
        elif resp.status_code == 401:
            status_text = "Unauthorized (Invalid JWT)"
        else:
            status_text = f"Status {resp.status_code}"

        raw_hex = binascii.hexlify(resp.content).decode('utf-8')

        return {
            "status": status_text,
            "code": resp.status_code,
            "bio": bio_text,
            "server_response": raw_hex
        }
    except Exception as e:
        return {"status": f"Error: {str(e)}", "code": 500, "bio": bio_text, "server_response": "N/A"}


# ===================== HOME =====================
@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "status": "✅ API Running",
        "version": FREEFIRE_VERSION,
        "server": "Multi-Region",
        "cors": "enabled",
        "endpoints": {
            "change_bio": {
                "url": "/bio",
                "methods": ["GET", "POST"],
                "usage_examples": [
                    "/bio?jwt={jwt}&bio=test",
                    "/bio?access_token={token}&bio=test",
                    "/bio?uid={uid}&pass={pass}&bio=test"
                ]
            }
        },
        "platform": "Vercel / Termux"
    })


# ===================== /bio =====================
@app.route("/bio", methods=["GET", "POST", "OPTIONS"])
def bio_endpoint():
    # Handle preflight CORS
    if request.method == "OPTIONS":
        response = make_response("", 204)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
        return response

    bio = request.args.get("bio") or request.form.get("bio")
    access_token = request.args.get("access_token") or request.form.get("access_token")
    uid = request.args.get("uid") or request.form.get("uid")
    password = request.args.get("pass") or request.args.get("password") or request.form.get("pass") or request.form.get("password")
    jwt_token = request.args.get("jwt") or request.form.get("jwt")

    if not bio:
        return jsonify({"status": "Error", "code": 400, "error": "Missing 'bio' parameter"}), 400

    final_jwt = None
    login_method = "N/A"
    final_access_token = None
    final_uid = None
    final_name = "Unknown"
    detected_region = DEFAULT_REGION

    # === CASE 1: Direct JWT ===
    if jwt_token:
        login_method = "Direct JWT"
        jwt_info = decode_jwt_full(jwt_token)
        if jwt_info:
            final_jwt = jwt_token
            final_uid = jwt_info.get("uid")
            final_name = jwt_info.get("name", "Unknown")
            detected_region = jwt_info.get("region") or DEFAULT_REGION
        else:
            return jsonify({"status": "Invalid JWT", "code": 400}), 400

    # === CASE 2: Access Token ===
    elif access_token:
        login_method = "Access Token Login"
        final_access_token = access_token
        jwt_token_from_at, account_uid, nickname, region = get_jwt_from_access_token(access_token)

        if jwt_token_from_at:
            final_jwt = jwt_token_from_at
            final_uid = account_uid
            final_name = nickname or "Unknown"
            detected_region = region or DEFAULT_REGION
            jwt_info = decode_jwt_full(final_jwt)
            if jwt_info:
                final_uid = jwt_info.get("uid") or final_uid
                final_name = jwt_info.get("name", final_name)
                detected_region = jwt_info.get("region") or detected_region
        else:
            return jsonify({"status": "Invalid Access Token", "code": 400}), 400

    # === CASE 3: UID + Password ===
    elif uid and password:
        login_method = "UID/Pass Login"
        jwt_token_from_up, account_uid, nickname, region = get_jwt_from_uid_password_api(uid, password)

        if jwt_token_from_up:
            final_jwt = jwt_token_from_up
            final_uid = account_uid
            final_name = nickname or "Unknown"
            detected_region = region or DEFAULT_REGION
            jwt_info = decode_jwt_full(final_jwt)
            if jwt_info:
                final_uid = jwt_info.get("uid") or final_uid
                final_name = jwt_info.get("name", final_name)
                detected_region = jwt_info.get("region") or detected_region
        else:
            return jsonify({"status": "Guest Login Failed (Check UID/Pass)", "code": 401}), 401

    else:
        return jsonify({
            "status": "Error",
            "code": 400,
            "error": "Provide jwt OR access_token OR uid+pass",
            "usage": [
                "/bio?jwt=TOKEN&bio=test",
                "/bio?access_token=TOKEN&bio=test",
                "/bio?uid=123456789&pass=password&bio=test"
            ]
        }), 400

    if not final_jwt:
        return jsonify({"status": "JWT Generation Failed", "code": 500}), 500

    mapped_region = map_region(detected_region)
    _, update_url = get_region_urls(mapped_region)
    result = upload_bio_request(final_jwt, bio, update_url)

    response_data = {
        "version": FREEFIRE_VERSION,
        "status": result["status"],
        "code": result["code"],
        "login_method": login_method,
        "player_name": final_name,
        "uid": str(final_uid) if final_uid else None,
        "region": mapped_region,
        "bio": result["bio"],
        "access_token": final_access_token,
        "generated_jwt": final_jwt,
        "server_response": result["server_response"]
    }

    response = make_response(jsonify(response_data))
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response.headers["Content-Type"] = "application/json"
    return response


# ========== HEALTH CHECK ==========
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "long-bio-ob55"})


# ========== ERROR HANDLERS ==========
@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "status": "Error",
        "code": 404,
        "error": "Endpoint not found",
        "available_endpoints": ["/", "/bio", "/health"]
    }), 404


# ========== TERMUX / LOCAL ==========
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"""
╔══════════════════════════════════════╗
║     🔥 FREE FIRE BIO API v3         ║
║     Version: {FREEFIRE_VERSION}                 ║
║     Server: Multi-Region             ║
║     CORS: Enabled ✅                 ║
║     Port: {port}                       ║
║                                      ║
║     /bio?jwt=TOKEN&bio=test          ║
║     /bio?access_token=TOKEN&bio=test ║
║     /bio?uid=123&pass=xxx&bio=test   ║
╚══════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=port, debug=False)