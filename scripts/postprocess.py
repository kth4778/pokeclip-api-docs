"""springdoc이 뽑은 문서를 다듬는다.

사용: python3 postprocess.py <서버이름> <파일>  (제자리 수정)

하는 일 둘:
1. auth에 한해 설명 주입 — 요약·상세·필드 설명. 코드에 @Operation이 없는
   동안의 임시 조치다. 코드에 없는 경로는 조용히 건너뛰므로 mono가 바뀌어도
   이 스크립트는 깨지지 않는다. 언젠가 mono에 어노테이션이 들어가면
   ENRICH를 비우면 된다.
2. 참조가 완전히 끊긴 스키마 제거(고정점까지 반복) — 지금은 아무것도
   안 지우지만(내부 API도 문서에 실으므로), 구조는 남겨 둔다.

**내부 서버 간 API(/internal/**)도 이 문서에 전부 싣는다.** 이 프로젝트는
서비스하지 않으므로 공격면을 가릴 이유가 없다 — 팀 안에서 계약을 한눈에
보는 것이 더 값지다. `internalToken` 시큐리티 스킴이 그 경계를 표시한다.

**알려진 구멍(보안 취약점 포함)도 관련 엔드포인트 설명에 그대로 적는다** —
CLAUDE.md에 이미 기록된 사실이고, 서비스를 안 할 것이므로 숨길 이유가 없다.

설명 문구는 전부 실제 컨트롤러·DTO·예외 핸들러·CLAUDE.md에서 확인한 사실이다.
추측으로 쓴 문장은 없다.
"""
import json
import re
import sys

INFO = {
    "auth": (
        "PokeClip Auth API",
        "로그인·토큰·스트림키를 담당하는 서버(포트 8082).\n\n"
        "- `bearerAuth` — 사용자 JWT. access 30분, refresh 14일\n"
        "- `internalToken` — 서버 간 호출(`X-Internal-Token` 헤더). Media·"
        "chat-collector가 쓴다\n"
        "- 인증 없음 — 로그인·토큰 재발급·로그아웃·페어링 코드 교환. "
        "토큰이 없어야 부를 수 있거나(로그인), 코드 자체가 자격증명이다(교환)\n\n"
        "**긴 비밀은 API로 조회할 수 없다.** streamid 원문을 저장하지 않아 줄 수 "
        "없고, passphrase는 페어링 코드 교환으로만 나간다.\n\n"
        "**이 프로젝트는 서비스하지 않는다.** 내부 API(`/internal/**`)와 알려진 "
        "보안 구멍까지 전부 문서에 실었다 — CLAUDE.md에 이미 적혀 있던 사실이고, "
        "가릴 이유가 없다.",
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
    ("/api/chzzk-link/start", "post"): (
        "치지직 연동 동의 URL 발급",
        "치지직 동의 화면으로 보낼 URL을 만든다. **state에 로그인한 사용자가 서명돼 있다** — "
        "콜백이 그 state로 요청자를 확인하므로 다른 사람 대신 연동을 완료시킬 수 없다.",
        [{"bearerAuth": []}], "치지직 연동", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/chzzk-link", "post"): (
        "치지직 연동 완료",
        "동의 콜백이 받은 `code`·`state`로 연동을 마무리한다. "
        "**연동될 채널은 요청 본문이 아니라 치지직 `me` 응답으로 확정한다** — "
        "클라이언트가 채널을 지어낼 수 없다.\n\n"
        "다른 계정에 이미 묶인 채널이면 거절된다(DB 유니크 인덱스가 최종 방어선 — "
        "인스턴스가 여럿이면 애플리케이션 락만으로는 안 되기 때문).",
        [{"bearerAuth": []}], "치지직 연동",
        {"400": key_err("state가 이 사용자 것이 아니거나 만료·위조(INVALID_STATE), "
                        "또는 치지직이 code 교환·me 조회를 4xx로 거부(INVALID_CODE) — "
                        "동의부터 다시 해야 한다.", "INVALID_STATE"),
         "401": UNAUTHORIZED_JWT,
         "409": key_err("이 채널이 이미 다른 계정에 연동돼 있다.", "CHANNEL_ALREADY_LINKED"),
         "502": key_err("치지직이 5xx·타임아웃·형식 오류를 냈다. 재시도 대상.", "CHZZK_UNAVAILABLE")},
    ),
    ("/api/chzzk-link", "get"): (
        "치지직 연동 상태 조회",
        "가장 최근 연동 행 기준으로 상태를 돌려준다. **연동이 끊긴 상태(BROKEN·UNLINKED)도 "
        "`channelName`은 함께 준다** — 화면이 \"어느 채널과 끊겼는지\"를 보여줄 수 있게.\n\n"
        "상태는 저장된 값이 아니라 `access_expires_at`·`revoked_at`·`revoke_reason`에서 "
        "**그때그때 계산**된다.",
        [{"bearerAuth": []}], "치지직 연동", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/chzzk-link", "delete"): (
        "치지직 연동 해제",
        "**멱등이다 — 연동이 이미 없어도 204.** 행은 지우지 않고 남긴다(`revoked_at`만 채운다). "
        "치지직 토큰(SecretStore의 access·refresh)은 이 시점에 버린다.",
        [{"bearerAuth": []}], "치지직 연동", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/editor-invitations", "post"): (
        "편집자 초대",
        "이메일로 편집자를 초대한다. **이메일 정확 일치만 된다** — 그 주소로 가입한 계정이 "
        "있어야 하고, 없으면 404다.\n\n"
        "**이미 보낸 초대에 다시 부르면 새 초대가 아니라 기한을 늘린다.** 그래도 응답은 "
        "201이다 — 클라이언트 입장에서 결과는 \"초대가 있다\"로 같다.\n\n"
        "계정당 살아있는 초대 상한은 **20건이지만 근사값이다** — \"세고 나서 쓴다\"라 "
        "동시에 서로 다른 상대를 여러 명 초대하면 넘는다(실측: PENDING 19 + 서로 다른 "
        "상대 8명 동시 → 27개 생성, 거부 0건). 정확히 막으려면 다른 회전 경로들과 같은 "
        "회원 행 락이 필요한데 대가가 더 크다고 판단했다.\n\n"
        "**알려진 보안 구멍 — 미인증 구글 이메일로 초대를 가로챌 수 있다.** "
        "`GoogleIdTokenVerifier`가 `email_verified`를 안 본다. 공격자가 피해자의 "
        "주소로 먼저 가입해 두면(구글 계정 자체는 미인증 이메일도 가입을 허용) "
        "그 주소로 오는 초대를 공격자가 받는다 — 피해자가 그 주소로 나중에 로그인하려 "
        "하면 `users.email` UNIQUE(V108)에 걸려 **가입이 거부**되므로 피해자는 시도조차 "
        "못 한다. 팀이 이 구멍을 인지한 채 보류하기로 결정했다(2026-08-18).",
        [{"bearerAuth": []}], "편집자 위임",
        {"400": key_err("자기 자신을 초대했다.", "SELF_INVITE"),
         "401": UNAUTHORIZED_JWT,
         "404": key_err("그 이메일로 가입한 계정이 없다.", "INVITEE_NOT_FOUND"),
         "409": key_err("이미 살아있는 위임이 있다(ALREADY_EDITOR), 또는 살아있는 초대가 "
                        "20건 상한에 찼다(TOO_MANY_PENDING — 위 설명대로 근사값).", "ALREADY_EDITOR")},
    ),
    ("/api/editor-invitations/sent", "get"): (
        "내가 보낸 초대 목록",
        "스트리머 시점 — 상대(초대받은 사람)의 이름·이메일·상태를 함께 준다.\n\n"
        "**페이징이 없다.** 살아있는 초대는 상한 20이 묶지만, 거절·취소·만료된 이력은 "
        "무한히 쌓이고 이 API가 전부 내보낸다.",
        [{"bearerAuth": []}], "편집자 위임", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/editor-invitations/received", "get"): (
        "내가 받은 초대 목록",
        "편집자 시점 — 상대(보낸 스트리머)의 이름을 준다. **이메일은 안 준다.** "
        "목록에는 응답 가능한(PENDING) 것만 담긴다.",
        [{"bearerAuth": []}], "편집자 위임", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/editor-invitations/{id}", "delete"): (
        "보낸 초대 취소",
        "**없는 초대에도 404다.** 존재 여부를 알려주지 않는다.",
        [{"bearerAuth": []}], "편집자 위임",
        {"401": UNAUTHORIZED_JWT,
         "404": key_err("없거나 남의 초대다.", "INVITATION_NOT_FOUND")},
    ),
    ("/api/editor-invitations/{id}/accept", "post"): (
        "초대 수락",
        "수락하면 위임이 생긴다. **7일이 지난 초대는 410**이다.",
        [{"bearerAuth": []}], "편집자 위임",
        {"401": UNAUTHORIZED_JWT,
         "404": key_err("없거나 남의 초대다.", "INVITATION_NOT_FOUND"),
         "409": key_err("이미 수락·거절·취소됐다.", "INVITATION_NOT_PENDING"),
         "410": key_err("만료된 초대다 (발급 후 7일).", "INVITATION_EXPIRED")},
    ),
    ("/api/editor-invitations/{id}/decline", "post"): (
        "초대 거절",
        "거절해도 초대 행은 남는다 — 상태만 DECLINED로 바뀐다.",
        [{"bearerAuth": []}], "편집자 위임",
        {"401": UNAUTHORIZED_JWT,
         "404": key_err("없거나 남의 초대다.", "INVITATION_NOT_FOUND"),
         "409": key_err("이미 수락·거절·취소됐다.", "INVITATION_NOT_PENDING"),
         "410": key_err("만료된 초대다 (발급 후 7일).", "INVITATION_EXPIRED")},
    ),
    ("/api/editor-delegations/as-streamer", "get"): (
        "내 편집자 목록",
        "내가 스트리머로서 위임한 편집자들. 살아있는 위임만 담긴다.",
        [{"bearerAuth": []}], "편집자 위임", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/editor-delegations/as-editor", "get"): (
        "내가 편집 중인 스트리머 목록",
        "내가 편집자로서 위임받은 스트리머들. 살아있는 위임만 담긴다.",
        [{"bearerAuth": []}], "편집자 위임", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/editor-delegations/{id}", "delete"): (
        "위임 해제",
        "**스트리머가 부르면 \"내보내기\", 편집자가 부르면 \"나가기\"다** — 같은 API를 "
        "양쪽이 쓴다. 행은 지우지 않고 `revokedAt`·`revokedBy`만 채운다.",
        [{"bearerAuth": []}], "편집자 위임",
        {"401": UNAUTHORIZED_JWT,
         "404": key_err("없거나 내 위임이 아니다.", "DELEGATION_NOT_FOUND")},
    ),
    ("/internal/stream-keys/resolve", "post"): (
        "스트림키 검증 (내부 전용)",
        "**Media 서버가 송출을 받아들일지 판단하려고 부른다.** Media가 DB를 직접 읽지 "
        "않고 이 API에 묻는다(계약4).\n\n"
        "**키가 틀려도 HTTP 200이다.** 본문의 `valid` 필드로 판정한다. Media에게 "
        "\"키가 틀림\"(연결 거절)과 \"Auth 장애\"(판단 불가)는 조치가 정반대인데, "
        "둘 다 4xx로 내보내면 구분할 수 없기 때문이다.\n\n"
        "거절 응답에는 `passphrase`·`userId`가 아예 나타나지 않는다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."}},
    ),
    ("/internal/chzzk-link/resolve", "post"): (
        "치지직 연동 조회 (내부 전용)",
        "**chat-collector가 회원 번호로 채널·access 토큰을 물어본다.** 이 응답의 "
        "`accessToken`이 채팅 수집기가 치지직 API를 부르는 데 쓰는 그 토큰이다 — "
        "만료가 임박하면 여기서 즉석 갱신 뒤 새 값을 준다.\n\n"
        "**항상 HTTP 200이다.** 미연동·만료·해제 전부 `valid:false`로 응답하고, "
        "\"수집 안 함\"과 \"Auth 장애\"를 상태 코드로 안 가른다(resolve 계약과 같은 원칙).",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."}},
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
    ("/api/chzzk-link/start", "post", "200"): "발급 성공.",
    ("/api/chzzk-link", "post", "201"): "연동 완료.",
    ("/api/chzzk-link", "get", "200"): "조회 성공.",
    ("/api/chzzk-link", "delete", "204"): "해제 완료(또는 이미 없었음). 본문이 없다.",
    ("/api/editor-invitations", "post", "201"): "초대 발송(또는 기한 연장) 완료.",
    ("/api/editor-invitations/sent", "get", "200"): "조회 성공.",
    ("/api/editor-invitations/received", "get", "200"): "조회 성공.",
    ("/api/editor-invitations/{id}", "delete", "204"): "취소 완료. 본문이 없다.",
    ("/api/editor-invitations/{id}/accept", "post", "204"): "수락 완료. 위임이 생겼다. 본문이 없다.",
    ("/api/editor-invitations/{id}/decline", "post", "204"): "거절 완료. 본문이 없다.",
    ("/api/editor-delegations/as-streamer", "get", "200"): "조회 성공.",
    ("/api/editor-delegations/as-editor", "get", "200"): "조회 성공.",
    ("/api/editor-delegations/{id}", "delete", "204"): "해제 완료. 본문이 없다.",
    ("/internal/stream-keys/resolve", "post", "200"):
        "판정 완료. **거절도 200이다** — `valid` 필드를 본다.",
    ("/internal/chzzk-link/resolve", "post", "200"):
        "판정 완료. 성공 시 `accessToken`이 실린다 — 이 응답이 그 토큰이 밖으로 "
        "나가는 유일한 경로다.",
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
    "StartResponse": {
        "_": "치지직 동의 URL.",
        "authorizeUrl": "이 주소로 사용자를 보낸다. state에 로그인한 사용자가 서명돼 있다.",
    },
    "LinkRequest": {
        "_": "동의 콜백이 받은 값 그대로.",
        "code": "치지직이 콜백에 실어 준 authorization code.",
        "state": "start에서 발급한 값. 요청자 확인에 쓰인다.",
    },
    "LinkResponse": {
        "_": "연동 완료 결과. 채널은 요청 본문이 아니라 치지직 me 응답으로 확정된 값이다.",
        "channelId": "연동된 치지직 채널ID.",
        "channelName": "연동된 채널명.",
        "linkedAt": "연동 완료 시각.",
    },
    "LinkStatusResponse": {
        "_": "연동 상태. 매 요청 시점의 계산값이다 — 저장된 상태 컬럼이 아니다.",
        "linked": "지금 유효한 연동이면 true. status가 ACTIVE·EXPIRED일 때만 true다.",
        "channelId": "연동(됐던) 채널ID. 한 번도 연동한 적 없으면 필드가 없다.",
        "channelName": "연동(됐던) 채널명. 끊긴 상태에도 표시용으로 남는다.",
        "status": "ACTIVE(정상)·EXPIRED(토큰 만료, 갱신 대기)·BROKEN(치지직이 갱신 거부)"
                  "·UNLINKED(사용자가 해제) 중 하나.",
        "linkedAt": "최초 연동 시각.",
        "lastRefreshedAt": "마지막으로 토큰을 확인·갱신한 시각.",
        "accessExpiresAt": "치지직 access 토큰 만료 시각.",
    },
    "InviteRequest": {
        "_": "초대 요청.",
        "email": "초대할 사람의 가입 이메일. 정확히 일치하는 계정이 있어야 한다.",
    },
    "SentInvitationResponse": {
        "_": "스트리머가 보는 초대 한 건. 상대(받는 사람)를 보여준다.",
        "id": "초대ID.",
        "inviteeId": "초대받은 사람의 회원ID.",
        "inviteeName": "초대받은 사람의 이름.",
        "inviteeEmail": "초대받은 사람의 이메일.",
        "status": "PENDING(응답 대기)·ACCEPTED(수락됨)·DECLINED(거절됨)·CANCELED(취소됨)"
                  "·EXPIRED(7일 경과, PENDING인 채로 기한만 지남) 중 하나.",
        "expiresAt": "만료 시각 (발송 후 7일).",
        "createdAt": "발송 시각. 기한을 연장해도 이 값은 안 바뀐다.",
    },
    "ReceivedInvitationResponse": {
        "_": "편집자가 보는 초대 한 건. 상대(보낸 스트리머)를 보여준다. "
             "**이메일은 안 준다.** 목록에는 응답 가능한(PENDING) 것만 담긴다.",
        "id": "초대ID.",
        "streamerId": "초대한 스트리머의 회원ID.",
        "streamerName": "초대한 스트리머의 이름.",
        "expiresAt": "만료 시각 (발송 후 7일).",
        "createdAt": "발송 시각.",
    },
    "DelegationResponse": {
        "_": "위임 한 건. 스트리머가 보면 상대가 편집자고, 편집자가 보면 상대가 스트리머다 — "
             "양쪽이 같은 모양을 쓴다. **이메일은 안 준다.**",
        "id": "위임ID.",
        "counterpartId": "상대방의 회원ID.",
        "counterpartName": "상대방의 이름.",
        "grantedAt": "위임이 생긴(초대를 수락한) 시각.",
    },
    "ResolveRequest": {
        "_": "Media가 보내는 검증 요청.",
        "streamid": "송출자가 제시한 stream id 원문.",
    },
    "ResolveResponse": {
        "_": "검증 결과. 거절이면 valid와 reason만 담긴다.",
        "valid": "이 키로 송출을 받아도 되면 true.",
        "userId": "키 주인. **거절 시에는 필드가 없다.**",
        "passphrase": "SRT 암호. **거절 시에는 필드가 없다.**",
        "reason": "거절 사유 — `MALFORMED`(형식 오류) · `NOT_FOUND`(없는 키) · "
                  "`REVOKED`(재발급으로 죽은 키). **성공 시에는 필드가 없다.**",
    },
    "ChzzkResolveRequest": {
        "_": "chat-collector가 보내는 조회 요청.",
        "userId": "채널·토큰을 물어볼 회원ID.",
    },
    "ChzzkResolveResponse": {
        "_": "조회 결과. 거절이면 valid와 reason만 담긴다.",
        "valid": "지금 이 회원의 채팅을 수집해도 되면 true.",
        "channelId": "치지직 채널ID. **거절 시에는 필드가 없다.**",
        "accessToken": "치지직 API 호출용 토큰. 만료 임박이면 즉석 갱신한 새 값이다. "
                       "**거절 시에는 필드가 없다.**",
        "expiresAt": "이 accessToken의 만료 시각. **거절 시에는 필드가 없다.**",
        "reason": "거절 사유 — `BROKEN`(치지직이 갱신 거부) · `REFRESH_UNAVAILABLE`"
                  "(즉석 갱신 실패, 일시적) · `UNLINKED`/`NOT_LINKED`(연동 안 됨). "
                  "**성공 시에는 필드가 없다.**",
    },
}

TAGS = [
    {"name": "인증", "description": "구글 로그인과 토큰 수명 관리."},
    {"name": "스트림키", "description": "OBS 송출용 비밀번호의 발급·재발급·플러그인 전달."},
    {"name": "치지직 연동", "description": "치지직 채널을 계정에 묶는다. 로그인(구글)과는 별개다."},
    {"name": "편집자 위임", "description": "스트리머가 편집자를 이메일로 초대하고, 수락하면 위임이 생긴다. "
                                       "권한 등급은 없다 — 위임되면 전부 할 수 있다."},
    {"name": "내부 (서버 간 연동)", "description": "Media·chat-collector만 부른다. "
                                             "사용자 JWT로는 통과할 수 없다(`internalToken`)."},
]


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
        "internalToken": {"type": "apiKey", "in": "header", "name": "X-Internal-Token",
                          "description": "Media·chat-collector만 쓴다. 배포 환경마다 값을 맞춘다."},
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
    for path, method, text in [
        ("/api/auth/logout", "post", "폐기 완료. 본문이 없다."),
        ("/api/chzzk-link", "delete", "해제 완료(또는 이미 없었음). 본문이 없다."),
        ("/api/editor-invitations/{id}", "delete", "취소 완료. 본문이 없다."),
        ("/api/editor-invitations/{id}/accept", "post", "수락 완료. 위임이 생겼다. 본문이 없다."),
        ("/api/editor-invitations/{id}/decline", "post", "거절 완료. 본문이 없다."),
        ("/api/editor-delegations/{id}", "delete", "해제 완료. 본문이 없다."),
    ]:
        responses = doc.get("paths", {}).get(path, {}).get(method, {}).get("responses")
        if responses and "200" in responses and "204" not in responses:
            responses["204"] = {"description": text}
            del responses["200"]
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

    internal = sum(1 for p in doc.get("paths", {}) if p.startswith("/internal"))
    print(f"{server}: 경로 {len(doc.get('paths', {}))}개(내부 {internal}개 포함), "
          f"스키마 {len(doc.get('components', {}).get('schemas', {}))}개")


if __name__ == "__main__":
    main()
