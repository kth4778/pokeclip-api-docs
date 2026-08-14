"""springdoc이 뽑은 문서를 공개용으로 다듬는다.

사용: python3 postprocess.py <서버이름> <파일>  (제자리 수정)

하는 일 셋:
1. /internal/** 경로 제거 — 이 사이트는 public이다. 팀 간 내부 계약의
   경로·헤더·요청 형식을 공개 문서에 싣지 않는다.
2. 남은 문서 어디서도 참조하지 않는 스키마 제거 — 1에서 지운 경로만 쓰던
   스키마(ResolveRequest 등)가 남아 있으면 지운 의미가 없다.
3. auth에 한해 설명 주입 — 요약·상세·필드 설명. 코드에 @Operation이 없는
   동안의 임시 조치다. 코드에 없는 경로는 조용히 건너뛰므로 mono가 바뀌어도
   이 스크립트는 깨지지 않는다. 언젠가 mono에 어노테이션이 들어가면
   ENRICH를 비우면 된다.

설명 문구는 전부 2026-08-11에 실제 컨트롤러·DTO·예외 핸들러에서 확인한
사실이다. 추측으로 쓴 문장은 없다.
"""
import json
import re
import sys

INFO = {
    "auth": (
        "PokeClip Auth API",
        "로그인·토큰·스트림키를 담당하는 서버(포트 8082).\n\n"
        "- `bearerAuth` — 사용자 JWT. access 30분, refresh 14일\n"
        "- 인증 없음 — 로그인·토큰 재발급·로그아웃·페어링 코드 교환. "
        "토큰이 없어야 부를 수 있거나(로그인), 코드 자체가 자격증명이다(교환)\n\n"
        "**긴 비밀은 API로 조회할 수 없다.** streamid 원문을 저장하지 않아 줄 수 "
        "없고, passphrase는 페어링 코드 교환으로만 나간다.\n\n"
        "내부 서버 간 API는 이 공개 문서에서 제외했다.",
    ),
    "clip": ("PokeClip Clip API", "방송 세션·클립·승인을 담당하는 서버(포트 8081). 아직 API가 없다."),
    "chat-collector": ("PokeClip Chat Collector API",
                       "치지직 채팅을 수집하는 서버(포트 8083). 수집은 나가는 연결이라 REST API가 없다."),
    "chat-detector": ("PokeClip Chat Detector API", "하이라이트를 판별하는 서버(포트 8084). 아직 API가 없다."),
}

AUTH_ERR = {
    "description": "인증 실패. **사유를 알려주지 않는다** — 만료·서명 오류·"
                   "계정 없음이 전부 같은 본문으로 나간다. 사유는 서버 로그에만 남는다.",
    "content": {"application/json": {
        "schema": {"type": "object", "properties": {"message": {"type": "string"}}},
        "example": {"message": "인증에 실패했습니다"},
    }},
}


def key_err(desc, reason):
    return {
        "description": desc,
        "content": {"application/json": {
            "schema": {"type": "object", "properties": {"reason": {"type": "string"}}},
            "example": {"reason": reason},
        }},
    }


UNAUTHORIZED_JWT = {"description": "access 토큰이 없거나 유효하지 않다."}

OPS = {
    ("/api/auth/google", "post"): (
        "구글 로그인",
        "구글에서 받은 authorization code를 우리 토큰 한 쌍으로 바꾼다.\n\n"
        "**처음 온 사용자는 이 호출로 자동 가입된다.** 별도 회원가입 API가 없다.\n"
        "로그인 수단은 구글 단독이다.",
        [], "인증", {"401": AUTH_ERR},
    ),
    ("/api/auth/me", "get"): (
        "내 정보 조회",
        "access 토큰의 주인 정보를 돌려준다.",
        [{"bearerAuth": []}], "인증", {"401": AUTH_ERR},
    ),
    ("/api/auth/refresh", "post"): (
        "토큰 재발급 (회전)",
        "refresh 토큰을 새 토큰 한 쌍으로 바꾼다. **쓴 refresh 토큰은 즉시 죽는다.**\n\n"
        "**이미 쓴 토큰이 다시 오면 탈취로 보고 그 사용자의 세션을 전부 끊는다.** "
        "그 경우에도 응답은 401 하나뿐이다.\n\n"
        "refresh 토큰을 쿼리스트링이 아니라 본문으로만 받는다 — "
        "접근 로그·프록시·브라우저 히스토리에 남기지 않기 위해서다.",
        [], "인증", {"401": AUTH_ERR},
    ),
    ("/api/auth/logout", "post"): (
        "로그아웃",
        "refresh 토큰을 폐기한다.\n\n**없는 토큰으로 불러도 204다.** 토큰의 존재 여부를 알려주지 않는다.",
        [], "인증", {"401": AUTH_ERR},
    ),
    ("/api/stream-keys", "get"): (
        "스트림키 발급 여부 조회",
        "키가 있는지와 발급 시각만 돌려준다. **키 값은 실리지 않는다.**\n\n"
        "웹이 재발급 버튼을 보여줄지 정하는 데 쓴다. "
        "재발급은 키가 없으면 404라, 이 API가 없으면 오류로 상태를 확인하게 된다.",
        [{"bearerAuth": []}], "스트림키", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/stream-keys/rotate", "post"): (
        "스트림키 재발급",
        "옛 키를 폐기하고 새 키를 만든다. **유예 기간이 없다 — 옛 키는 즉시 죽는다.** "
        "유출 대응이 목적이기 때문이다.\n\n"
        "**응답에 새 키 값이 실리지 않는다.** 사람은 페어링 코드로만 받는다.",
        [{"bearerAuth": []}], "스트림키",
        {"401": UNAUTHORIZED_JWT,
         "404": key_err("폐기할 키가 없다. 아직 한 번도 발급받지 않은 계정이다.", "STREAM_KEY_NOT_FOUND")},
    ),
    ("/api/stream-keys/pairing-codes", "post"): (
        "페어링 코드 발급",
        "OBS 플러그인에 스트림키를 넘기기 위한 일회용 코드를 만든다. "
        "**유효 시간 10분, 한 번 쓰면 죽는다.**\n\n"
        "사람이 눈으로 읽고 옮겨 적는 코드라 짧다. "
        "짧아도 되는 이유는 만료와 사용량 제한이 함께 걸려 있기 때문이다.\n\n"
        "**계정당 분당 3회**까지 발급할 수 있다.",
        [{"bearerAuth": []}], "스트림키",
        {"401": UNAUTHORIZED_JWT,
         "429": key_err("발급 한도 초과 (계정당 분당 3회).", "PAIRING_CODE_RATE_LIMITED")},
    ),
    ("/api/stream-keys/pairing-codes/exchange", "post"): (
        "페어링 코드 → 스트림키 교환",
        "**OBS 플러그인이 부른다. 로그인하지 않는다** — 코드 자체가 자격증명이다.\n\n"
        "긴 비밀(`streamid`·`passphrase`)이 밖으로 나가는 **유일한 경로**다. "
        "웹 화면에서는 이 값을 볼 수 없다.\n\n"
        "**IP당 분당 5회**까지 시도할 수 있다. 거부당한 시도도 세므로, "
        "429를 맞은 뒤에도 한도는 계속 소모된다.",
        [], "스트림키",
        {"404": key_err("그런 코드가 없다.", "PAIRING_CODE_NOT_FOUND"),
         "409": key_err("이미 사용된 코드다.", "PAIRING_CODE_ALREADY_USED"),
         "410": key_err("만료된 코드다 (발급 후 10분).", "PAIRING_CODE_EXPIRED"),
         "429": key_err("시도 한도 초과 (IP당 분당 5회).", "PAIRING_CODE_RATE_LIMITED")},
    ),
}

OK_DESC = {
    ("/api/auth/google", "post", "200"): "로그인 성공. 토큰 한 쌍을 돌려준다.",
    ("/api/auth/me", "get", "200"): "조회 성공.",
    ("/api/auth/refresh", "post", "200"): "회전 성공. 새 토큰 한 쌍을 돌려준다.",
    ("/api/auth/logout", "post", "204"): "폐기 완료. 본문이 없다.",
    ("/api/stream-keys", "get", "200"): "조회 성공.",
    ("/api/stream-keys/rotate", "post", "200"): "재발급 완료.",
    ("/api/stream-keys/pairing-codes", "post", "201"): "발급 완료.",
    ("/api/stream-keys/pairing-codes/exchange", "post", "200"):
        "교환 성공. **이 응답이 긴 비밀을 담는 유일한 곳이다.**",
}

FIELDS = {
    "GoogleLoginRequest": {
        "_": "구글 로그인 요청.",
        "code": "구글 OAuth authorization code. 프론트가 구글 동의 화면에서 받아 온다.",
    },
    "TokenResponse": {
        "_": "우리 서비스의 토큰 한 쌍.",
        "accessToken": "API 호출에 쓰는 JWT. **30분** 뒤 만료된다.",
        "refreshToken": "재발급에 쓰는 토큰. **14일**. 서버에는 SHA-256 해시만 저장된다.",
    },
    "MeResponse": {
        "_": "로그인한 사용자 정보.",
        "id": "사용자 id. access 토큰의 sub와 같은 값이다.",
        "email": "구글 계정 이메일.",
        "name": "구글 프로필 이름.",
        "profileImageUrl": "구글 프로필 사진 주소.",
    },
    "RefreshRequest": {
        "_": "재발급·로그아웃 공용 요청.",
        "refreshToken": "로그인이나 직전 회전에서 받은 refresh 토큰.",
    },
    "StreamKeyStatusResponse": {
        "_": "스트림키 발급 여부. **키 값은 담기지 않는다.**",
        "issued": "살아 있는 키가 있으면 true.",
        "createdAt": "발급 시각. 키가 없으면 이 필드가 나타나지 않는다.",
    },
    "RotateResponse": {
        "_": "재발급 결과. **새 키 값이 담기지 않는다** — 페어링 코드로만 받는다.",
        "rotatedAt": "재발급 시각. 이 시각부로 옛 키는 죽었다.",
    },
    "PairingCodeResponse": {
        "_": "발급된 일회용 코드.",
        "code": "사람이 읽어 플러그인에 옮겨 적는 코드.",
        "expiresAt": "만료 시각 (발급 후 10분).",
    },
    "ExchangeRequest": {
        "_": "코드 교환 요청.",
        "code": "웹에서 발급받은 페어링 코드. 대소문자·하이픈 차이는 서버가 흡수한다.",
    },
    "ExchangeResponse": {
        "_": "OBS 플러그인이 받는 최종 송출 자격증명. **다시 조회할 수 없다.**",
        "streamid": "SRT 송출 주소에 넣는 stream id.",
        "passphrase": "SRT 암호. **이 응답에서만 나간다.**",
    },
}

TAGS = [
    {"name": "인증", "description": "구글 로그인과 토큰 수명 관리."},
    {"name": "스트림키", "description": "OBS 송출용 비밀번호의 발급·재발급·플러그인 전달."},
]


def strip_internal(doc):
    removed = [p for p in doc.get("paths", {}) if p.startswith("/internal")]
    for p in removed:
        del doc["paths"][p]
    return removed


def gc_schemas(doc):
    """남은 문서 어디서도 참조하지 않는 스키마를 지운다. 참조가 사라지면서
    또 참조가 끊기는 연쇄가 있을 수 있어 고정점까지 반복한다."""
    schemas = doc.get("components", {}).get("schemas", {})
    while True:
        body = json.dumps({k: v for k, v in doc.items() if k != "components"} |
                          {"components": {k: v for k, v in doc.get("components", {}).items()
                                          if k != "schemas"}}, ensure_ascii=False)
        body += json.dumps(schemas, ensure_ascii=False)
        dead = []
        for name in list(schemas):
            ref = f'#/components/schemas/{name}"'
            others = body.replace(json.dumps(schemas.get(name), ensure_ascii=False), "", 1)
            if ref not in others:
                dead.append(name)
        if not dead:
            return
        for name in dead:
            del schemas[name]


def enrich_auth(doc):
    doc.setdefault("components", {})["securitySchemes"] = {
        "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT",
                       "description": "로그인으로 받은 access 토큰. 30분 만료."},
    }
    for (path, method), (summary, desc, sec, tag, extra) in OPS.items():
        op = doc.get("paths", {}).get(path, {}).get(method)
        if op is None:
            continue
        op["summary"] = summary
        op["description"] = desc
        op["security"] = sec
        op["tags"] = [tag]
        op.setdefault("responses", {}).update(extra)
    for (path, method, code), text in OK_DESC.items():
        resp = doc.get("paths", {}).get(path, {}).get(method, {}).get("responses", {}).get(code)
        if resp is not None:
            resp["description"] = text
    # springdoc은 @ResponseStatus(NO_CONTENT)를 못 읽고 200으로 적는다.
    logout = doc.get("paths", {}).get("/api/auth/logout", {}).get("post", {}).get("responses")
    if logout and "200" in logout and "204" not in logout:
        logout["204"] = {"description": "폐기 완료. 본문이 없다."}
        del logout["200"]
    for name, spec in FIELDS.items():
        schema = doc.get("components", {}).get("schemas", {}).get(name)
        if schema is None:
            continue
        schema["description"] = spec["_"]
        for field, text in spec.items():
            if field != "_" and field in schema.get("properties", {}):
                schema["properties"][field]["description"] = text
    doc["tags"] = TAGS


def main():
    server, path = sys.argv[1], sys.argv[2]
    with open(path) as f:
        doc = json.load(f)

    removed = strip_internal(doc)
    gc_schemas(doc)

    title, desc = INFO[server]
    doc["info"] = {"title": title, "version": doc.get("info", {}).get("version", "v1"),
                   "description": desc}
    # 추출 환경의 localhost 주소는 의미가 없다. 지운다.
    doc.pop("servers", None)

    if server == "auth":
        enrich_auth(doc)

    with open(path, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"{server}: 경로 {len(doc.get('paths', {}))}개, "
          f"스키마 {len(doc.get('components', {}).get('schemas', {}))}개, "
          f"내부 경로 {len(removed)}개 제거")


if __name__ == "__main__":
    main()
