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
    "clip": (
        "PokeClip Clip API",
        "방송 세션·점프카드·구간 조회를 담당하는 서버(포트 8081).\n\n"
        "- `bearerAuth` — 사용자 JWT. 편집기가 쓰는 문이 여기 있다\n"
        "- `internalToken` — 판별기가 카드를 넣는 문(`/internal/**`)\n\n"
        "**방송 이벤트는 API가 아니라 SQS로 받는다** — 그쪽은 문서에 안 나온다.\n\n"
        "`GET /api/clip/broadcasts/{streamId}/events`는 **SSE(Server-Sent Events)**다. "
        "일반 JSON 응답이 아니라 연결을 열어 두고 카드를 밀어 준다."),
    "chat-collector": (
        "PokeClip Chat Collector API",
        "치지직 채팅을 수집하는 서버(포트 8083).\n\n"
        "**수집 자체는 나가는 연결이라 API가 없다.** 여기 있는 둘은 clip이 물어보는 "
        "내부 창구뿐이다 — 둘 다 `internalToken`이 필요하고 사용자 JWT로는 못 들어온다."),
    "chat-detector": (
        "PokeClip Chat Detector API",
        "채팅이 갑자기 몰리는 순간을 찾아내는 서버(포트 8084).\n\n"
        "**API가 하나도 없다. 하지만 코드가 없는 것은 아니다** — 이 서버는 부르는 쪽이지 "
        "불리는 쪽이 아니다. 스케줄러가 한 바퀴마다 활성 방송을 골라 `chat_messages`를 "
        "3·5·10초 창으로 집계해 `chat_metrics`에 쌓고, 평소보다 튄 창을 찾으면 "
        "clip의 `POST /internal/broadcasts/{streamId}/highlights`로 보낸다.\n\n"
        "발행은 판정 스레드가 아니라 별도 실행기에서 한다 — clip이 죽어 있을 때 "
        "재시도가 판정을 멈추면 안 되기 때문이다. 쌓이는 표는 ERD의 `chat_metrics`를 본다."),
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

OPS = {}
OPS["auth"] = {
    ("/api/auth/google", "post"): (
        "구글 로그인",
        "구글에서 받은 authorization code를 우리 토큰 한 쌍으로 바꾼다.\n\n"
        "**처음 온 사용자는 이 호출로 자동 가입된다.** 별도 회원가입 API가 없다.\n"
        "로그인 수단은 구글 단독이다.",
        [], "인증", {"401": AUTH_ERR},
    ),
    ("/api/auth/me", "get"): (
        "내 정보 조회",
        "access 토큰의 주인 정보를 돌려준다. **회원 번호를 넘기지 않는다** — 토큰이 누구인지를 정한다.\n\n"
        "`profileImageUrl`이 **10분마다 바뀐다**(직접 올린 사진일 때). 그래서 이 응답을 "
        "화면 상태에 통째로 덮어써도 그림이 깜빡이지 않는다 — 10분 안에는 같은 글자가 나온다.",
        [{"bearerAuth": []}], "내 정보", {"401": AUTH_ERR},
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
    ("/api/auth/me", "patch"): (
        "내 이름 수정",
        "표시 이름만 바꾼다. **사진은 이 문이 아니다** — 본문 형식이 달라 "
        "`PUT /api/auth/me/photo`로 갈라져 있다.\n\n"
        "누구를 고칠지는 **토큰이 정한다.** 본문에 `userId`를 실어도 무시된다.\n\n"
        "**앞뒤 공백은 서버가 잘라 낸다** — 전각 공백·NBSP·제로폭 공백까지 자른다. "
        "자르고 나서 보이는 글자가 없으면 `NAME_BLANK`다.\n\n"
        "**길이는 30자**다. 이모지 하나가 1자로 센다(코드 포인트 기준).\n\n"
        "**응답은 `GET /api/auth/me`와 똑같은 모양**이라 그대로 상태에 덮어쓰면 된다 — "
        "고친 뒤 다시 조회할 필요가 없다.",
        [{"bearerAuth": []}], "내 정보",
        {"400": key_err(
            "이름이 규칙에 안 맞는다. **`reason`으로 갈라 안내한다** — "
            "`NAME_BLANK`(비었다) · `NAME_TOO_LONG`(30자 초과) · "
            "`NAME_INVALID_CHARACTER`(줄바꿈·탭 같은 제어문자가 섞였다). "
            "**거부된 이름은 응답에 안 실린다.**", "NAME_TOO_LONG"),
         "401": UNAUTHORIZED_JWT},
    ),
    ("/api/auth/me/photo", "put"): (
        "프로필 사진 올리기",
        "**`multipart/form-data`다.** 파트 이름은 `file` 하나뿐이다.\n\n"
        "**PUT인 이유** — 사람마다 사진이 하나고 덮어쓴다. 여러 번 눌러도 결과가 같다.\n\n"
        "받는 형식은 **PNG·JPEG·WebP** 셋이고, **파일 크기는 2MB**까지다"
        "(멀티파트 전체로는 3MB).\n\n"
        "🔴 **확장자나 Content-Type을 보지 않는다** — 파일 앞부분의 실제 바이트로 판정한다. "
        "`.png`로 이름을 바꾼 다른 파일은 415로 거절된다.\n\n"
        "**응답이 바로 새 사진 주소를 싣는다**(`GET /api/auth/me`와 같은 모양) — "
        "올린 뒤 다시 조회하지 말고 이 응답으로 화면을 갈아 끼우면 된다.\n\n"
        "**사진을 올리면 구글 사진 주소는 지워진다.** 되돌리는 문은 없다.",
        [{"bearerAuth": []}], "내 정보",
        {"401": UNAUTHORIZED_JWT,
         "413": key_err("파일이 2MB를 넘는다. 화면은 「줄여서 다시」를 안내한다.", "PHOTO_TOO_LARGE"),
         "415": key_err("그림이 아니다. 앞부분 바이트가 PNG·JPEG·WebP 중 무엇도 아니다.",
                        "PHOTO_NOT_AN_IMAGE"),
         "503": key_err("사진 창고(S3)가 꺼져 있다. **사용자 잘못이 아니다** — "
                        "화면은 「잠시 뒤 다시」를 안내한다. 로컬·CI의 기본 상태이기도 하다.",
                        "PHOTO_STORAGE_DISABLED")},
    ),
    ("/api/profile-photos/{userId}", "get"): (
        "프로필 사진 내려받기",
        "**JSON이 아니라 이미지 바이트를 그대로 준다.** `<img src=...>`에 그대로 넣는 주소다.\n\n"
        "🔴 **이 주소를 직접 조립하지 마라.** `GET /api/auth/me`·수정·업로드 응답의 "
        "`profileImageUrl`을 **받은 그대로** 쓴다 — 뒤에 붙은 `token`이 서명값이라 "
        "손으로 만들 수 없다.\n\n"
        "**토큰 없이 열리는 유일한 문이다**(로그인 안 해도 된다). 그림 태그는 인증 헤더를 "
        "못 싣기 때문이고, 그래서 자격을 주소에 실린 표가 대신한다 — 그 표로 열 수 있는 것은 "
        "사진 한 장뿐이고 **10분이면 죽는다.**\n\n"
        "**주소는 10분 동안 안 바뀐다** — 회원 정보를 자주 다시 불러도 브라우저가 같은 그림을 "
        "다시 받지 않는다. 사진을 바꾸면 즉시 다른 주소가 된다.",
        [], "내 정보",
        {"404": {"description":
                 "🔴 **거절이 전부 여기로 온다** — 표가 틀렸든, 만료됐든, 그 사람이 사진을 "
                 "안 올렸든, 그런 회원이 아예 없든 **응답이 똑같다.** 갈라 주면 "
                 "「그 사람이 사진을 올렸는가」가 새어 나가기 때문이다. "
                 "화면은 이 경우 이니셜을 그리면 된다."}},
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
    ("/api/youtube-link/start", "post"): (
        "유튜브 연동 동의 URL 발급",
        "구글 동의 화면으로 보낼 URL을 만든다. **state에 로그인한 사용자가 서명돼 있다.**\n\n"
        "치지직과 같은 모양이지만 **동의 화면에서 채널을 고르는 것이 구글 쪽 UI**라는 점이 다르다 — "
        "브랜드 계정이 여럿이면 여기서 하나를 고르고, 그 선택이 그대로 굳는다.",
        [{"bearerAuth": []}], "유튜브 연동", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/youtube-link", "post"): (
        "유튜브 연동 완료",
        "동의 콜백이 받은 `code`·`state`로 연동을 마무리한다. "
        "**채널은 요청 본문이 아니라 구글 `channels.list`로 확정한다.**\n\n"
        "🔴 **채널 목록·재선택 API가 없다.** 구글은 동의 시점에 채널을 확정하고, 그 토큰으로는 "
        "고른 채널 **하나만** 조회된다(2026-08-24 실측 — 브랜드 계정도 개인 계정도 `totalResults:1`). "
        "채널을 바꾸는 유일한 방법은 **이 API를 다시 부르는 것**(재연동)이다.",
        [{"bearerAuth": []}], "유튜브 연동",
        {"400": key_err("state가 이 사용자 것이 아니거나 만료·위조(INVALID_STATE), 구글이 code 교환을 "
                        "거부(INVALID_CODE), 또는 그 계정에 채널이 없다(NO_CHANNEL).", "INVALID_STATE"),
         "401": UNAUTHORIZED_JWT,
         "409": key_err("이 채널이 이미 다른 계정에 연동돼 있다.", "CHANNEL_ALREADY_LINKED"),
         "502": key_err("구글이 5xx·타임아웃·형식 오류를 냈다. 재시도 대상.", "YOUTUBE_UNAVAILABLE")},
    ),
    ("/api/youtube-link", "get"): (
        "유튜브 연동 상태 조회",
        "가장 최근 연동 행 기준. 끊긴 상태(BROKEN·UNLINKED)도 `channelName`은 함께 준다.\n\n"
        "**치지직과 상태 값이 다르다 — `EXPIRED`가 없다.** 구글 access 토큰은 1시간짜리라 "
        "늘 만료돼 있고 갱신으로 항상 해소되므로, 그것을 상태로 두면 정상인데 문제처럼 보인다. "
        "여기서 `linked`는 `status == ACTIVE`와 같다.",
        [{"bearerAuth": []}], "유튜브 연동", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/youtube-link", "delete"): (
        "유튜브 연동 해제",
        "**멱등이다 — 연동이 이미 없어도 204.** 행은 남기고(`revoked_at`) 토큰 원문만 지운다.\n\n"
        "🔴 **구글에는 revoke를 보내지 않는다.** 구글의 revoke는 「그 토큰」이 아니라 "
        "**「그 계정이 이 앱에 준 동의 전부」**를 죽인다(2026-08-25 실측) — 같은 채널을 연동한 "
        "다른 회원의 연동까지 함께 끊긴다. 그래서 우리가 지우는 것은 **우리 쪽 참조까지**이고, "
        "구글 계정에 남은 권한은 사용자가 `myaccount.google.com/permissions`에서 직접 지운다.",
        [{"bearerAuth": []}], "유튜브 연동", {"401": UNAUTHORIZED_JWT},
    ),
    ("/internal/youtube-link/resolve", "post"): (
        "유튜브 토큰 조회 (내부 전용)",
        "**업로드 워커가 회원 번호로 채널·access 토큰을 받아 간다.** 남은 수명이 "
        "**30분 미만이면 즉석에서 갱신**해 새 토큰을 준다.\n\n"
        "**항상 200이다.** 미연동·끊김도 `valid:false`로 답한다 — 「업로드를 안 한다」와 "
        "「Auth 장애」는 조치가 정반대인데 둘 다 4xx면 구분할 수 없다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."}},
    ),
    ("/internal/editor-delegations/resolve", "post"): (
        "위임 관계 판정 (내부 전용)",
        "**clip이 「이 사람이 저 스트리머의 데이터를 볼 수 있나」를 묻는다.** "
        "답은 `relation` 하나 — `OWNER`(본인) · `EDITOR`(위임받음) · `NONE`(권한 없음).\n\n"
        "**항상 200이다.** `NONE`도 정상 응답이다 — 남의 방송 링크를 열어보는 것은 "
        "흔한 일이라 오류로 다루지 않는다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."}},
    ),
    ("/internal/editor-delegations/accessible", "post"): (
        "볼 수 있는 스트리머 목록 (내부 전용)",
        "**한 사람이 접근 가능한 스트리머 전부.** 본인이 항상 `OWNER`로 포함된다.\n\n"
        "**목록에 없으면 곧 `NONE`이다** — 이 응답에 `NONE`은 나오지 않는다. "
        "본인이 첫 줄에 오지만 clip은 **순서가 아니라 `relation` 값으로** 찾아야 한다.",
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

OK_DESC = {}
OK_DESC["auth"] = {
    ("/api/auth/google", "post", "200"): "로그인 성공. 토큰 한 쌍을 돌려준다.",
    ("/api/auth/me", "get", "200"): "조회 성공.",
    ("/api/auth/me", "patch", "200"): "수정 완료. **바뀐 정보를 그대로 돌려준다** — 다시 조회하지 않아도 된다.",
    ("/api/auth/me/photo", "put", "200"):
        "업로드 완료. **새 사진 주소가 실린 회원 정보**를 돌려준다 — 이 응답으로 화면을 갈아 끼운다.",
    ("/api/profile-photos/{userId}", "get", "200"):
        "이미지 바이트. **JSON이 아니다** — `Content-Type`은 우리가 판정한 형식"
        "(`image/png`·`image/jpeg`·`image/webp`)이고, 브라우저가 내용으로 다시 추측하지 못하게 "
        "`X-Content-Type-Options: nosniff`를 함께 보낸다.",
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
    ("/api/youtube-link/start", "post", "200"): "발급 성공.",
    ("/api/youtube-link", "post", "201"): "연동 완료.",
    ("/api/youtube-link", "get", "200"): "조회 성공.",
    ("/api/youtube-link", "delete", "204"): "해제 완료(또는 이미 없었음). 본문이 없다.",
    ("/internal/youtube-link/resolve", "post", "200"):
        "판정 완료. 성공 시 `accessToken`이 실린다 — 필요하면 즉석 갱신한 새 값이다.",
    ("/internal/editor-delegations/resolve", "post", "200"): "판정 완료. `NONE`도 200이다.",
    ("/internal/editor-delegations/accessible", "post", "200"): "조회 성공.",
    ("/internal/chzzk-link/resolve", "post", "200"):
        "판정 완료. 성공 시 `accessToken`이 실린다 — 이 응답이 그 토큰이 밖으로 "
        "나가는 유일한 경로다.",
}

FIELDS = {}
FIELDS["auth"] = {
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
        "_": "로그인한 사용자 정보. **조회·이름 수정·사진 업로드가 전부 이 모양으로 답한다** — "
             "고친 뒤 다시 조회할 필요가 없다.",
        "id": "회원 번호. access 토큰의 `sub`와 같은 값이고 **서비스 전체에서 유일하다.** "
              "편집자 위임·점프카드의 `claimedBy`가 가리키는 것도 이 번호다.",
        "email": "구글 계정 이메일. **바꿀 수 없다** — 편집자 초대가 이 값으로 상대를 찾는다.",
        "name": "표시 이름. 처음엔 구글 프로필 이름이고 `PATCH /api/auth/me`로 바꾼다. "
                "**재로그인해도 구글 값으로 되돌아가지 않는다.**",
        "profileImageUrl": "그림 태그에 그대로 넣는 주소.\n\n"
                           "**두 종류가 같은 칸으로 온다** — 사진을 올렸으면 우리 주소"
                           "(`/api/profile-photos/{id}?token=...`), 안 올렸으면 구글 주소다. "
                           "화면은 구분할 필요가 없다.\n\n"
                           "🔴 **`null`일 수 있다** — 구글이 사진을 안 줬거나, 올린 사진의 창고가 "
                           "꺼져 있을 때다. 그때는 이니셜을 그린다.\n\n"
                           "**직접 조립하지 마라.** 뒤의 `token`이 서명값이다.",
    },
    "UpdateNameRequest": {
        "_": "이름 수정 요청. **`userId`를 실어도 무시된다** — 누구를 고칠지는 토큰이 정한다.",
        "name": "새 표시 이름. 앞뒤 공백은 서버가 자르고, 자른 뒤 **1~30자**여야 한다"
                "(이모지 하나 = 1자). 줄바꿈·탭 같은 제어문자는 거절된다.",
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
    "ChzzkStartResponse": {
        "_": "치지직 동의 URL.",
        "authorizeUrl": "이 주소로 사용자를 보낸다. state에 로그인한 사용자가 서명돼 있다.",
    },
    "ChzzkLinkRequest": {
        "_": "동의 콜백이 받은 값 그대로.",
        "code": "치지직이 콜백에 실어 준 authorization code.",
        "state": "start에서 발급한 값. 요청자 확인에 쓰인다.",
    },
    "ChzzkLinkResponse": {
        "_": "연동 완료 결과. 채널은 요청 본문이 아니라 치지직 me 응답으로 확정된 값이다.",
        "channelId": "연동된 치지직 채널ID.",
        "channelName": "연동된 채널명.",
        "linkedAt": "연동 완료 시각.",
    },
    "ChzzkLinkStatusResponse": {
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
    "YoutubeStartResponse": {
        "_": "구글 동의 URL.",
        "authorizeUrl": "이 주소로 사용자를 보낸다. 동의 화면에서 채널을 고르고, 그 선택이 굳는다.",
    },
    "YoutubeLinkRequest": {
        "_": "동의 콜백이 받은 값 그대로.",
        "code": "구글이 콜백에 실어 준 authorization code.",
        "state": "start에서 발급한 값. 요청자 확인에 쓰인다.",
    },
    "YoutubeLinkResponse": {
        "_": "연동 완료 결과. 채널은 구글 channels.list로 확정된 값이다.",
        "channelId": "연동된 유튜브 채널ID.",
        "channelName": "연동된 채널명.",
        "linkedAt": "연동 완료 시각.",
    },
    "YoutubeLinkStatusResponse": {
        "_": "유튜브 연동 상태. **치지직과 달리 EXPIRED가 없다** — 구글 access는 1시간짜리라 "
             "늘 만료돼 있고 갱신으로 항상 해소되므로 상태로 두지 않는다.",
        "linked": "지금 유효한 연동이면 true. `status == ACTIVE`와 같은 뜻이다.",
        "channelId": "연동(됐던) 채널ID. 한 번도 연동한 적 없으면 필드가 없다.",
        "channelName": "연동(됐던) 채널명. 끊긴 상태에도 표시용으로 남는다.",
        "status": "ACTIVE(정상)·BROKEN(구글이 갱신을 거부 — 사용자가 권한을 지웠거나 만료)"
                  "·UNLINKED(사용자가 해제) 중 하나.",
        "linkedAt": "최초 연동 시각.",
        "lastRefreshedAt": "마지막으로 토큰을 확인·갱신한 시각.",
        "accessExpiresAt": "구글 access 토큰 만료 시각(보통 1시간 뒤).",
    },
    "YoutubeResolveRequest": {
        "_": "업로드 워커가 보내는 조회 요청.",
        "userId": "채널·토큰을 물어볼 회원ID.",
    },
    "YoutubeResolveResponse": {
        "_": "조회 결과. 거절이면 valid와 reason만 담긴다.",
        "valid": "지금 이 회원의 채널로 업로드해도 되면 true.",
        "channelId": "유튜브 채널ID. **거절 시에는 필드가 없다.**",
        "accessToken": "구글 API 호출용 토큰. 남은 수명이 30분 미만이면 즉석 갱신한 새 값이다. "
                       "**거절 시에는 필드가 없다.**",
        "expiresAt": "이 accessToken의 만료 시각. **거절 시에는 필드가 없다.**",
        "reason": "거절 사유 — `BROKEN`(구글이 갱신 거부) · `REFRESH_UNAVAILABLE`(즉석 갱신 실패, "
                  "일시적) · `UNLINKED`/`NOT_LINKED`(연동 안 됨). **성공 시에는 필드가 없다.**",
    },
    "DelegationResolveRequest": {
        "_": "clip이 보내는 판정 요청.",
        "userId": "판정 대상 — 「이 사람이」.",
        "streamerUserId": "기준 스트리머 — 「저 스트리머의 데이터를 볼 수 있나」.",
    },
    "DelegationResolveResponse": {
        "_": "판정 결과. 항상 200이고 이 필드 하나로 끝난다.",
        "relation": "OWNER(본인)·EDITOR(위임받은 편집자)·NONE(권한 없음) 중 하나.",
    },
    "AccessibleStreamersRequest": {
        "_": "볼 수 있는 스트리머 목록 요청.",
        "userId": "이 사람이 접근 가능한 목록을 묻는다.",
    },
    "AccessibleStreamersResponse": {
        "_": "접근 가능한 스트리머 전부. **목록에 없으면 곧 NONE**이라 NONE 항목은 안 실린다.",
        "streamers": "본인(OWNER)이 항상 포함된다. 첫 줄에 오지만 순서가 아니라 relation으로 찾아야 한다.",
    },
    "Entry": {
        "_": "접근 가능한 스트리머 한 명.",
        "streamerUserId": "스트리머의 회원ID.",
        "relation": "OWNER(본인)·EDITOR(위임받음) 중 하나. NONE은 여기 안 나온다.",
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

# 경로·쿼리 파라미터 설명. springdoc은 이름과 타입만 뽑아 주고 **뜻은 못 만든다** —
# 프론트가 "여기 뭘 넣어야 하나"를 코드를 읽지 않고 알 수 있어야 해서 손으로 적는다.
#   PARAMS[서버][(경로, 메서드)] = {파라미터 이름: 설명}
PARAMS = {}

# springdoc 이 코드에서 **못 읽는 것**을 손으로 바로잡는 자리. 설명(OPS)과 달리 이것은 모양이다.
#   body    — 본문을 @RequestBody 가 아니라 요청 스트림·JsonNode 로 읽는 문(스펙에 본문이 비거나 뜻 없는 객체로 나온다)
#   status  — ResponseEntity.status(런타임 값) 으로 201·204 를 내는 문(스펙에는 200 만 남는다)
#   params  — @RequestParam MultiValueMap 을 받는 중계 문(스펙에 'query' 뭉치 하나로 나온다)
#   ok      — 200 본문 모양. 중계 문처럼 문자열을 그대로 넘기는 자리
OP_FIX = {}

# 스키마 이름을 사람이 읽기 좋게 바꾼다. 줄이기 규칙이 겹침만 가르므로 유일한데 뜻이 안 보이는 이름이 남는다.
SCHEMA_ALIAS = {}

PARAMS["auth"] = {
    ("/api/profile-photos/{userId}", "get"): {
        "userId": "사진 주인의 회원 번호. **직접 넣지 말고** `profileImageUrl`을 통째로 쓴다.",
        "token": "주소에 딸려 오는 서명값. **손으로 만들 수 없고** 10분이면 죽는다. "
                 "없거나 틀리면 404다(있는 사진인지도 안 알려준다).",
    },
    ("/api/editor-invitations/{id}", "delete"): {
        "id": "취소할 초대의 번호. `GET /api/editor-invitations/sent`의 `id`다.",
    },
    ("/api/editor-invitations/{id}/accept", "post"): {
        "id": "수락할 초대의 번호. `GET /api/editor-invitations/received`의 `id`다.",
    },
    ("/api/editor-invitations/{id}/decline", "post"): {
        "id": "거절할 초대의 번호. `GET /api/editor-invitations/received`의 `id`다.",
    },
    ("/api/editor-delegations/{id}", "delete"): {
        "id": "해제할 위임의 번호. **초대 번호가 아니다** — "
              "`as-streamer`·`as-editor` 목록의 `id`를 쓴다.",
    },
}

TAGS = {}
TAGS["auth"] = [
    {"name": "인증", "description": "구글 로그인과 토큰 수명 관리."},
    {"name": "내 정보", "description": "로그인한 사람의 이름·사진. 조회·수정·사진 올리기가 여기 있고, "
                                    "사진을 내보내는 공개 주소도 같이 둔다."},
    {"name": "스트림키", "description": "OBS 송출용 비밀번호의 발급·재발급·플러그인 전달."},
    {"name": "치지직 연동", "description": "치지직 채널을 계정에 묶는다. 로그인(구글)과는 별개다."},
    {"name": "편집자 위임", "description": "스트리머가 편집자를 이메일로 초대하고, 수락하면 위임이 생긴다. "
                                       "권한 등급은 없다 — 위임되면 전부 할 수 있다."},
    {"name": "유튜브 연동", "description": "유튜브 채널을 계정에 묶는다. 완성된 클립을 올릴 곳이다. "
                                       "채널은 동의 시점에 확정되고 재연동으로만 바꾼다."},
    {"name": "내부 (서버 간 연동)", "description": "다른 서버만 부른다 — Media·clip·chat-collector·업로드 워커. "
                                             "사용자 JWT로는 통과할 수 없다(`internalToken`)."},
]

# @ResponseStatus(NO_CONTENT)를 springdoc이 못 읽어 200으로 적는 자리들.
NO_CONTENT = {
    "auth": [("/api/youtube-link", "delete", "해제 완료(또는 이미 없었음). 본문이 없다.")],
}


# ─────────────────────────── clip (8081) ───────────────────────────

def clip_err(desc, code, extra=None):
    """clip의 오류 봉투는 전부 `{"error": "..."}` 한 모양이다(칸이 더 붙는 것도 있다)."""
    example = {"error": code}
    if extra:
        example.update(extra)
    props = {"error": {"type": "string"}}
    if extra:
        props.update({k: {"type": "string"} for k in extra})
    return {"description": desc,
            "content": {"application/json": {
                "schema": {"type": "object", "properties": props}, "example": example}}}


# 🔴 자격이 없는 것과 방송이 없는 것이 **같은 404**다. 갈라 주면 남의 방송 이름을 넣어 보는
# 것만으로 그 방송의 실재를 알 수 있어서다. 응답 시간까지 맞춰 두었다.
CLIP_404 = clip_err(
    "그런 방송이 없거나, **볼 자격이 없다.** 🔴 **둘을 구분해 주지 않는다** — "
    "남의 방송 번호를 넣어 보는 것만으로 그 방송의 존재를 알 수 없게 하려는 것이다. "
    "화면은 「없는 방송입니다」 하나로 안내하면 된다.", "broadcast_not_found")

CLIP_503_AUTH = clip_err(
    "**자격을 확인하지 못했다** — auth 서버에 못 닿았다. 🔴 **「권한 없음」이 아니다.** "
    "빈 목록이나 404로 접지 말고 「잠시 뒤 다시」를 안내한다 — 그러지 않으면 서버가 살아난 뒤에도 "
    "사용자가 다시 시도하지 않는다.", "authorization_unavailable")

CLIP_401 = {"description": "access 토큰이 없거나 유효하지 않다."}

CLIP_400_FIELD = clip_err(
    "요청 값이 잘못됐다. **`field`가 어느 칸인지 알려준다.**", "invalid_request", {"field": "limit"})

OPS["clip"] = {
    ("/api/clip/broadcasts", "get"): (
        "방송 목록 조회",
        "**편집자가 홈 화면을 열 때 처음 부르는 문.** 내가 볼 수 있는 스트리머들의 방송을 준다 — "
        "내 방송과, 나를 편집자로 위임한 스트리머의 방송이 함께 온다.\n\n"
        "**「방송 중」과 「지난 방송」을 한 목록에 안 섞는다**(`state`가 필수인 이유). "
        "섞으면 오래 켜 둔 방송이 첫 장 밖으로 밀려 라이브 표시가 안 뜬다.\n\n"
        "**최신 방송이 먼저 온다.**\n\n"
        "**다음 장은 `nextCursor`를 그대로 되돌려 넣는다** — 풀어 보거나 만들지 않는다. "
        "`null`이면 마지막 장이다.\n\n"
        "🔴 **누구 것을 볼지는 토큰이 정한다.** 스트리머 번호를 넘기는 칸이 없다.",
        [{"bearerAuth": []}], "편집기",
        {"400": clip_err(
            "요청 값이 잘못됐다. `field`가 어느 칸인지 알려준다 — "
            "`state`(`live`·`past` 말고 다른 값. **대소문자를 가린다**) · "
            "`limit`(0 이하) · `cursor`(우리가 준 표시가 아니다. **카드 목록에서 받은 표시를 "
            "여기 넣어도 400이다**).", "invalid_request", {"field": "state"}),
         "401": CLIP_401,
         "503": CLIP_503_AUTH},
    ),
    ("/api/clip/broadcasts/{streamId}/jump-cards", "get"): (
        "점프카드 목록 조회",
        "**방송 화면을 열 때 지금까지의 카드를 받아 가는 문.**\n\n"
        "🔴 **실시간 통로(SSE)와 짝이다.** 통로는 「이 뒤로 생긴 것」만 주므로, 화면은 "
        "**통로를 먼저 열고 → 이 문으로 지금까지의 카드를 받는다.** 순서를 뒤집으면 "
        "그 사이에 생긴 카드를 놓친다. 겹쳐 오는 것은 `id`로 덮어쓴다.\n\n"
        "**카드 한 장의 모양이 통로로 오는 것과 칸 하나까지 같다.**\n\n"
        "**방송 시간 순(빠른 것 먼저)으로 온다** — 영상 타임라인에 그대로 얹는 순서다.\n\n"
        "**숨긴 카드는 기본으로 빠진다.** `includeHidden=true`로 함께 받는다.\n\n"
        "**다음 장은 `nextCursor`를 그대로 되돌려 넣는다.** `null`이면 마지막 장이다.",
        [{"bearerAuth": []}], "편집기",
        {"400": clip_err(
            "요청 값이 잘못됐다. `field`가 어느 칸인지 알려준다 — "
            "`limit`(0 이하) · `cursor`(우리가 준 표시가 아니다. **방송 목록에서 받은 표시를 "
            "여기 넣어도 400이다**) · `includeHidden`(true·false가 아니다).",
            "invalid_request", {"field": "limit"}),
         "401": CLIP_401,
         "404": CLIP_404,
         "503": CLIP_503_AUTH},
    ),
    ("/api/clip/broadcasts/{streamId}/segments", "get"): (
        "구간 조각 조회",
        "편집기가 **「이 구간을 지금 볼 수 있나」**를 묻는 문이다. `startMs`~`endMs`에 걸친 "
        "영상 조각 목록을 준다.\n\n"
        "**`complete`가 핵심이다** — 요청한 구간이 조각으로 다 덮였는지를 알려준다. "
        "`false`면 아직 안 올라온 부분이 있다는 뜻이라 조금 뒤 다시 물으면 된다.\n\n"
        "**`availableFromMs`·`availableUntilMs`는 요청 구간보다 넓을 수 있다** — 조각 경계라서다. "
        "그대로 재생 시작·끝점으로 쓰면 요청보다 긴 영상이 나온다(자르는 것은 호출자 몫).\n\n"
        "**S3 키는 주지 않는다.** 버킷이 비공개라 지금 줘도 화면이 못 쓰고, 우리 버킷 이름 규칙만 "
        "밖으로 나간다. 조각은 `seq`로 가리킨다.",
        [{"bearerAuth": []}], "편집기",
        {"400": clip_err("구간이 잘못됐다 — `startMs >= endMs`이거나, 음수이거나, "
                         "**폭이 30분을 넘는다.** `field`가 어느 칸인지 알려준다.",
                         "invalid_request", {"field": "endMs"}),
         "401": CLIP_401,
         "404": CLIP_404,
         "410": clip_err("**보관 기한이 지났다.** 방송 기록은 남아 있지만 영상은 이미 지워졌다 — "
                         "404와 갈라 주는 이유가 그것이다(「없는 방송」이 아니다). "
                         "화면은 「보관 만료」를 그린다.", "vod_expired"),
         "503": CLIP_503_AUTH},
    ),
    ("/api/clip/broadcasts/{streamId}/events", "get"): (
        "점프카드 실시간 수신 (SSE)",
        "🔴 **일반 JSON API가 아니다. SSE(Server-Sent Events)** — 연결을 열어 두면 서버가 "
        "카드를 밀어 준다. `Content-Type: text/event-stream`.\n\n"
        "🔴 **연결해도 지금 있는 카드는 안 온다. 여기서 오는 것은 「이 뒤로 생기거나 바뀐 것」뿐이다.**\n\n"
        "**그래서 화면은 두 문을 같이 쓴다** — 순서가 정해져 있다:\n"
        "1. 먼저 **이 통로를 연다**\n"
        "2. 그 다음 `GET /api/clip/broadcasts/{streamId}/jump-cards`로 지금까지의 카드를 받는다\n\n"
        "**통로가 먼저인 이유** — 목록을 받는 동안 새로 생긴 카드를 놓치지 않으려는 것이다. "
        "반대로 하면 그 사이의 카드가 영영 안 온다. 겹쳐 오는 카드는 `id`로 덮어쓰면 된다.\n\n"
        "각 이벤트의 `data`는 **카드 한 장**이고, 목록 문이 주는 카드와 **칸 하나까지 같은 모양**이다.\n\n"
        "방송이 끝나면 `ended` 이벤트가 오고 서버가 연결을 닫는다. "
        "연결 수명은 최대 **4시간**이고, access 토큰이 먼저 만료되면 **그 시점에 닫힌다** — "
        "화면은 새 토큰으로 다시 연결한다.\n\n"
        "`Last-Event-ID` 헤더(또는 `lastEventId` 파라미터)를 받긴 하지만 **지금은 아무 일도 안 한다.** "
        "재연결 뒤 빠진 카드를 메우는 것은 목록 문의 몫이다.",
        [{"bearerAuth": []}], "편집기",
        {"401": clip_err("access 토큰이 없거나, 유효하지 않거나, **이미 만료됐다**"
                         "(`token_expired`). 새 토큰으로 다시 연결한다.", "token_expired"),
         "404": CLIP_404,
         "503": clip_err(
             "동시 연결 상한에 걸렸다. **`scope`가 무엇에 걸렸는지 알려준다** — "
             "`user`(이 사람이 탭을 너무 많이 열었다 → 「다른 탭을 닫아라」) · "
             "`stream`(이 방송에 사람이 몰렸다) · `total`(서버 전체) → 뒤 둘은 「잠시 뒤 다시」다.\n\n"
             "**본문은 JSON이다** — 연결이 서기 전에 끝나므로 event-stream이 아니다.",
             "stream_limit", {"scope": "user"})},
    ),
    ("/api/clip/jump-cards/{id}/claim", "post"): (
        "점프카드 집기",
        "**「내가 이 카드를 편집한다」고 찍는다.** 편집자 여러 명이 같은 카드를 동시에 "
        "건드리는 것을 막는 자리다.\n\n"
        "집은 상태에는 **시한(TTL)이 있다** — `claimExpiresAt`이 지나면 자동으로 풀린 것으로 본다. "
        "치우는 배경 작업이 없어서 집을 때 판정하므로, 그 값은 표에 저장된 값이 아니라 계산값이다.",
        [{"bearerAuth": []}], "편집기",
        {"401": CLIP_401,
         "404": clip_err(
             "그런 카드가 없거나, **이 방송을 볼 자격이 없다.** 🔴 **구분해 주지 않는다** — 카드 번호를 훑어 보는 것도 같은 종류의 탐색이라서다.", "jump_card_not_found"),
         "409": {"description":
                 "다른 사람이 이미 집었고 아직 시한이 안 지났다.\n\n"
                 "🔴 **본문이 오류 봉투가 아니라 「현재 카드」다** — 누가 언제까지 잡고 있는지가 "
                 "그대로 실려 온다. 화면은 다시 조회하지 말고 이 응답으로 카드를 갱신하면 된다.",
                 "content": {"application/json": {
                     "schema": {"$ref": "#/components/schemas/JumpCardSnapshot"}}}},
         "503": CLIP_503_AUTH},
    ),
    ("/api/clip/jump-cards/{id}/claim", "delete"): (
        "점프카드 놓기",
        "집은 것을 스스로 푼다. 시한이 지나기를 기다리지 않고 바로 남에게 넘길 때 쓴다.\n\n"
        "**아무도 안 집은 카드를 놓아도 204다** — 화면이 상태를 먼저 확인할 필요가 없다.",
        [{"bearerAuth": []}], "편집기",
        {"401": CLIP_401,
         "403": clip_err("**남이 집은 카드는 못 놓는다.** 이 문은 「내가 집은 것을 내가 푼다」 전용이다.",
                         "not_claim_owner"),
         "404": clip_err(
             "그런 카드가 없거나, **이 방송을 볼 자격이 없다.** 🔴 **구분해 주지 않는다** — 카드 번호를 훑어 보는 것도 같은 종류의 탐색이라서다.", "jump_card_not_found"),
         "503": CLIP_503_AUTH},
    ),
    ("/api/clip/jump-cards/{id}/hide", "post"): (
        "점프카드 숨기기",
        "쓸모없는 카드를 목록에서 치운다. **행을 지우지 않고 `hidden` 표시만 한다** — "
        "판별기가 왜 이걸 골랐는지 나중에 되짚을 수 있어야 해서다.\n\n"
        "숨긴 카드는 목록 문의 기본 응답에서 빠진다 — `includeHidden=true`로 다시 부르면 보인다.",
        [{"bearerAuth": []}], "편집기",
        {"401": CLIP_401,
         "404": clip_err(
             "그런 카드가 없거나, **이 방송을 볼 자격이 없다.** 🔴 **구분해 주지 않는다** — 카드 번호를 훑어 보는 것도 같은 종류의 탐색이라서다.", "jump_card_not_found"),
         "503": CLIP_503_AUTH},
    ),
    ("/api/clip/jump-cards/{id}/hide", "delete"): (
        "점프카드 되돌리기",
        "숨긴 것을 다시 꺼낸다.\n\n"
        "**숨긴 사람이 아니어도 누구나 되돌릴 수 있다** — 숨긴 사람만 가능하게 하면 "
        "그 사람이 자리를 비웠을 때 아무도 못 되돌린다.\n\n"
        "숨겨져 있지 않은 카드를 되돌려도 성공이다.",
        [{"bearerAuth": []}], "편집기",
        {"401": CLIP_401,
         "404": clip_err(
             "그런 카드가 없거나, **이 방송을 볼 자격이 없다.** 🔴 **구분해 주지 않는다** — 카드 번호를 훑어 보는 것도 같은 종류의 탐색이라서다.", "jump_card_not_found"),
         "503": CLIP_503_AUTH},
    ),
    ("/internal/broadcasts/{streamId}/highlights", "post"): (
        "점프카드 넣기 (내부 전용)",
        "**판별기가 「여기가 하이라이트다」를 넣는 문**이다(계약 2A).\n\n"
        "**201과 200을 가른다** — 새로 만들었으면 201, 같은 `eventId`가 이미 있으면 200이다. "
        "판별기가 재전송했을 때 로그에서 중복과 진짜 신규를 구분할 수 있게 한 것이라 "
        "**둘 다 성공**이다(재시도는 안전하다).",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        # 🔴 springdoc이 201을 못 만든다 — 코드가 ResponseEntity.status(런타임 값)로 가르기
        # 때문이다(반환 타입만 봐서는 안 보인다). 여기서 손으로 넣지 않으면 스펙에 200만 남아,
        # 「201과 200을 가른다」는 설명이 응답 목록과 어긋난다.
        {"201": {"description": "**새 카드를 만들었다.**",
                 "content": {"application/json": {
                     "schema": {"$ref": "#/components/schemas/JumpCardSnapshot"}}}},
         "400": clip_err("요청이 잘못됐다 — 창이 뒤집혔거나(`startMs >= endMs`), 지점이 창 밖이거나, "
                         "`eventId`가 128자를 넘거나, 모르는 `source`다. "
                         "**재시도해도 같은 결과라 판별기는 멈춰야 한다.**",
                         "invalid_request", {"field": "windowEndMs"}),
         "401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."},
         "404": clip_err("그런 방송이 없다. **자격 판정은 여기 없다** — 이 문은 서버 간 토큰으로 "
                         "들어오므로 감출 상대가 없다.", "broadcast_not_found")},
    ),
}
OK_DESC["clip"] = {
    ("/api/clip/broadcasts", "get", "200"):
        "조회 성공. **볼 수 있는 방송이 없으면 빈 목록이 온다**(404가 아니다).",
    ("/api/clip/broadcasts/{streamId}/jump-cards", "get", "200"):
        "조회 성공. 아직 카드가 없으면 빈 목록이다.",
    ("/api/clip/broadcasts/{streamId}/segments", "get", "200"): "조회 성공.",
    ("/api/clip/broadcasts/{streamId}/events", "get", "200"):
        "연결됨. **여기서 끝이 아니라 이제부터 이벤트가 흘러온다**(text/event-stream).",
    ("/api/clip/jump-cards/{id}/claim", "post", "200"): "집기 성공. 갱신된 카드를 돌려준다.",
    ("/api/clip/jump-cards/{id}/claim", "delete", "204"): "놓기 완료. 본문이 없다.",
    ("/api/clip/jump-cards/{id}/hide", "post", "200"): "숨김 완료. 갱신된 카드를 돌려준다.",
    ("/api/clip/jump-cards/{id}/hide", "delete", "200"): "되돌림 완료. 갱신된 카드를 돌려준다.",
    ("/internal/broadcasts/{streamId}/highlights", "post", "200"):
        "**이미 있던 카드다**(같은 eventId 재전송). 성공으로 다뤄도 된다.",
}
FIELDS["clip"] = {
    "SegmentWindowResponse": {
        "_": "요청한 구간에 걸친 조각 목록. **S3 키는 실리지 않는다.**",
        "complete": "요청 구간이 조각으로 전부 덮였으면 true. false면 아직 안 올라온 부분이 있다.",
        "availableFromMs": "실제로 덮인 시작 지점. **조각 경계라 요청보다 이를 수 있다.**",
        "availableUntilMs": "실제로 덮인 끝 지점. **조각 경계라 요청보다 늦을 수 있다.**",
        "segments": "조각 목록.",
    },
    # 🔴 이름이 "Item"이 아니다. POK-174가 BroadcastListResponse.Item을 만들면서 단순 이름이
    # 둘이 됐고, 축약기가 SegmentItem·BroadcastItem으로 갈랐다 — 그 순간 여기 있던 "Item"
    # 설명이 **아무 스키마에도 안 붙게 됐다.** 오류도 경고도 없었다.
    # 아래 report_unmatched가 이제 그런 자리를 CI 출력에 찍는다.
    "SegmentWindowItem": {
        "_": "조각 하나. 내부 모델의 여섯 칸 중 넷만 나간다.",
        "seq": "조각 번호. 실제 파일은 이 번호로 가리킨다(S3 키 대신).",
        "startPtsMs": "조각 시작 재생 시각(ms).",
        "durationMs": "조각 길이(ms).",
        "discontinuity": "이 조각 앞에 방송 재연결(끊김→복구) 경계가 있었다. "
                         "**여기를 넘어 이어 붙이면 안 된다.**",
    },
    "HighlightRequest": {
        "_": "판별기가 넣는 카드 한 장(계약 2A).",
        "eventId": "판별기가 매긴 고유 번호. **같은 값이 다시 오면 새로 만들지 않는다**(멱등). 128자 이내.",
        "source": "무엇이 이 순간을 골랐는지.",
        "streamTimestampMs": "하이라이트 지점(방송 시작 기준 ms). **창 안에 있어야 한다.**",
        "window": "잘라낼 구간.",
        "score": "판별기가 매긴 점수. 없어도 된다.",
        "evidence": "판별 근거. 구조가 자유로운 JSON이라 그대로 담는다.",
    },
    # 같은 이름의 중첩 record가 둘이라 바깥 클래스 이름으로 가른다(shorten_schema_names).
    # HighlightRequest.Window → HighlightRequestWindow · JumpCardSnapshot.Window → JumpCardWindow
    "HighlightRequestWindow": {
        "_": "잘라낼 구간(요청).",
        "startMs": "구간 시작(방송 시작 기준 ms).",
        "endMs": "구간 끝. **startMs보다 커야 한다.**",
    },
    "JumpCardWindow": {
        "_": "잘라낼 구간(응답).",
        "startMs": "구간 시작(방송 시작 기준 ms).",
        "endMs": "구간 끝.",
    },
    "JumpCardSnapshot": {
        "_": "카드 한 장. **SSE와 HTTP 응답이 같은 모양을 쓴다** — 2번(web)과의 계약이라 "
             "칸 이름을 바꾸지 않는다.",
        "id": "카드ID.",
        "streamId": "이 카드가 속한 방송.",
        "source": "무엇이 이 순간을 골랐는지.",
        "streamTimestampMs": "하이라이트 지점(방송 시작 기준 ms).",
        "window": "잘라낼 구간.",
        "score": "판별기 점수. 없을 수 있다.",
        "evidence": "판별 근거(자유 JSON).",
        "claimedBy": "집은 사람의 **회원 번호**. **이름이 아니다** — 이름표는 auth가 갖고 있다.",
        "claimedAt": "집은 시각.",
        "claimExpiresAt": "집은 상태가 풀리는 시각. **표에 없는 계산값**이라 TTL 설정을 바꾸면 즉시 반영된다.",
        "hidden": "숨겨졌으면 true.",
        "hiddenBy": "숨긴 사람의 회원 번호.",
        "eventSeq": "이 카드의 변경 순번. SSE로 온 것과 대조할 때 쓴다.",
        "createdAt": "카드가 생긴 시각.",
    },
    "JumpCardListResponse": {
        "_": "카드 한 장의 모양이 **실시간 통로로 오는 것과 똑같다** — 화면이 두 벌로 처리하지 않아도 된다.",
        "cards": "카드 목록. **방송 시간 순(빠른 것 먼저)**이다.",
        "nextCursor": "다음 장을 받을 때 `cursor`에 **그대로** 넣는 값. "
                      "**풀어 보거나 만들지 않는다.** `null`이면 마지막 장이다.",
    },
    "BroadcastListResponse": {
        "_": "방송 목록 한 장.",
        "broadcasts": "방송 목록. **최신 것이 먼저** 온다.",
        "nextCursor": "다음 장을 받을 때 `cursor`에 **그대로** 넣는 값. "
                      "**방송 목록용과 카드 목록용이 서로 안 통한다**(넣으면 400). "
                      "`null`이면 마지막 장이다.",
    },
    "BroadcastListItem": {
        "_": "방송 한 줄.",
        "streamId": "방송을 가리키는 이름. **카드 목록·통로·조각 조회에 이 값을 넣는다.**",
        "status": "`live`(방송 중) · `ended`(끝남) · `vod_ready`(다시보기 준비됨). **소문자다.**",
        "relation": "내가 이 방송의 스트리머와 무슨 사이인지 — "
                    "`OWNER`(내 방송) · `EDITOR`(위임받아 편집한다). "
                    "**둘의 권한은 같다** — 화면에 「내 방송」 표시를 다는 데 쓴다.",
        "startedAt": "방송 시작 시각. 🔴 **`null`일 수 있다** — 종료 신호가 시작보다 먼저 도착한 "
                     "방송이다. 지어내지 않는다. 화면은 「시작 시각 미상」으로 그린다.",
        "endedAt": "방송 종료 시각. 방송 중이면 `null`이다.",
        "vodExpiresAt": "다시보기 보관 만료 시각. **이 시각이 지나도 방송 줄은 목록에 남는다** — "
                        "기록은 남고 영상만 사라진다. 화면은 이 값으로 「보관 만료」를 그리고, "
                        "조각 조회는 그때 410을 준다.",
    },
}
PARAMS["clip"] = {
    ("/api/clip/broadcasts", "get"): {
        "state": "🔴 **필수.** `live`(방송 중) 또는 `past`(지난 방송). **소문자로만 받는다** — "
                 "`LIVE`는 400이다. 두 덩어리를 한 목록에 섞지 않는다.",
        "limit": "한 장에 받을 개수. 안 주면 **20**, 최대 **100**(넘겨 달라고 해도 깎는다). "
                 "**0 이하는 400**이다.",
        "cursor": "다음 장 표시. 직전 응답의 `nextCursor`를 **그대로** 넣는다. "
                  "첫 장은 안 넣거나 빈 문자열이다. **카드 목록에서 받은 표시는 여기서 400**이다.",
    },
    ("/api/clip/broadcasts/{streamId}/jump-cards", "get"): {
        "streamId": "방송 목록의 `streamId`.",
        "includeHidden": "숨긴 카드도 함께 받을지. 안 주면 `false`(뺀다).",
        "limit": "한 장에 받을 개수. 안 주면 **50**, 최대 **200**. **0 이하는 400**이다.",
        "cursor": "다음 장 표시. 직전 응답의 `nextCursor`를 **그대로** 넣는다. "
                  "**방송 목록에서 받은 표시는 여기서 400**이다.",
    },
    ("/api/clip/broadcasts/{streamId}/events", "get"): {
        "streamId": "방송 목록의 `streamId`.",
        "Last-Event-ID": "브라우저 `EventSource`가 재연결할 때 자동으로 붙이는 헤더. "
                         "🔴 **지금은 아무 일도 안 한다** — 빠진 카드는 목록 문으로 메운다.",
        "lastEventId": "위 헤더를 못 쓸 때의 대체 칸. **마찬가지로 지금은 아무 일도 안 한다.**",
    },
    ("/api/clip/broadcasts/{streamId}/segments", "get"): {
        "streamId": "방송 목록의 `streamId`.",
        "startMs": "구간 시작(방송 시작을 0으로 잡은 ms). 음수면 400이다.",
        "endMs": "구간 끝. `startMs`보다 커야 하고, **폭이 30분을 넘으면 400**이다.",
    },
    ("/api/clip/jump-cards/{id}/claim", "post"): {"id": "집을 카드의 번호(`JumpCardSnapshot.id`)."},
    ("/api/clip/jump-cards/{id}/claim", "delete"): {"id": "놓을 카드의 번호. **내가 집은 것만** 놓을 수 있다."},
    ("/api/clip/jump-cards/{id}/hide", "post"): {"id": "숨길 카드의 번호."},
    ("/api/clip/jump-cards/{id}/hide", "delete"): {"id": "되돌릴 카드의 번호. **누가 숨겼든 상관없다.**"},
    ("/internal/broadcasts/{streamId}/highlights", "post"): {
        "streamId": "카드를 넣을 방송. clip의 방송 명부에 있어야 한다(없으면 404).",
    },
}

TAGS["clip"] = [
    {"name": "편집기", "description":
        "편집자가 쓰는 문. 사용자 JWT가 필요하고, 그 방송을 볼 권한이 있는지 auth에 물어 확인한다.\n\n"
        "🔴 **권한이 없으면 403이 아니라 404다** — 「없는 방송」과 구분해 주지 않는다. "
        "auth에 못 닿아 확인 자체가 안 되면 **503**이고, 그때는 「권한 없음」이 아니라 "
        "「잠시 뒤 다시」다."},
    {"name": "내부 (서버 간 연동)", "description": "판별기만 부른다. 사용자 JWT로는 통과할 수 없다."},
]
NO_CONTENT["clip"] = [("/api/clip/jump-cards/{id}/claim", "delete", "놓기 완료. 본문이 없다.")]

# ────────────────────── chat-collector (8083) ──────────────────────
OPS["chat-collector"] = {
    ("/internal/streams/{streamId}/chat-collection", "get"): (
        "채팅 수집 상태 조회 (내부 전용)",
        "**clip이 「이 방송의 채팅을 지금 받고 있나」를 묻는다.** 화면의 「수집 중」 배너가 "
        "이 값으로 켜지고 꺼진다.\n\n"
        "**항상 200이다.** 모르는 방송도 `unknown`으로 답한다 — 404면 clip이 "
        "「그런 방송 없음」과 「수집 서버 장애」를 구분할 수 없다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."}},
    ),
    ("/internal/streams/{streamId}/video-position", "get"): (
        "채팅 시각 → 영상 위치 변환 (내부 전용)",
        "**채팅이 찍힌 시각을 그 방송 영상 안의 재생 위치로 바꿔 준다.** "
        "「이 채팅이 터진 순간」으로 영상을 점프시키는 데 쓴다.\n\n"
        "`messageTime`은 epoch ms(`1787529601000`) 또는 ISO-8601(`2026-08-24T12:00:00Z`)로 준다.\n\n"
        "🔴 **`+09:00` 같은 오프셋 표기도 되지만 `+`를 `%2B`로 인코딩해야 한다** — "
        "쿼리 스트링에서 `+`는 공백으로 디코드돼 그대로 치면 400이 난다.\n\n"
        "**`positionMs`는 영상 전체 기준 절대 위치**이고 `segmentSeq`는 참고값이다 — "
        "둘을 「이 조각 파일 안에서의 오프셋」 쌍으로 쓰면 경계에서 어긋난다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"400": {"description": "시각 형식이 틀렸거나 받아 주는 범위(1970~2200년) 밖이다. "
                                "단위 착각(ms 자리에 나노초)이 여기 걸린다."},
         "401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."},
         "500": {"description": "**삼키지 않고 그대로 낸다** — 표가 없거나 DB가 죽은 것이다. "
                                "「조각이 아직 안 들어옴」과 완전히 다른 상태라 그럴듯한 답으로 덮지 않는다."}},
    ),
}
OK_DESC["chat-collector"] = {
    ("/internal/streams/{streamId}/chat-collection", "get", "200"):
        "조회 성공. **모르는 방송도 여기로 온다**(`state: unknown`).",
    ("/internal/streams/{streamId}/video-position", "get", "200"): "변환 성공.",
}
FIELDS["chat-collector"] = {
    "ChatCollectionStatus": {
        "_": "수집 상태 한 장. 필드 이름은 2번(web)·clip과의 약속이다.",
        "streamId": "물어본 방송.",
        "state": "`establishing`(붙는 중)·`collecting`(정상 수집)·`reconnecting`(끊겨서 재시도 중)"
                 "·`stopped`(포기)·`unknown`(모르는 방송) 등 소문자 값.",
        "since": "문제가 시작된 시각. 정상이면 없다. **`stopped`인데도 없을 수 있다** — "
                 "포기 기록이 남기 전에는 그 시각을 아무도 안 들고 있어서 지어내지 않는다.",
        "attempt": "재시도 횟수. `reconnecting`일 때만 뜻이 있다.",
        "needsRelink": "true면 **사용자가 치지직을 다시 연동해야** 복구된다. `stopped`일 때만 뜻이 있다.",
        "donationState": "후원 구독 상태 — `none`·`subscribed`·`refused`·`failed`. **채팅 수집과 따로 논다**: "
                         "`state=collecting` 인데 여기가 `refused` 인 것이 정상이다(토큰에 후원 권한만 없는 경우). "
                         "모르는 방송은 `null` 이 아니라 `none` 이다.",
        "observedAt": "이 답을 만든 시각.",
    },
}
PARAMS["chat-collector"] = {
    ("/internal/streams/{streamId}/chat-collection", "get"): {
        "streamId": "물어볼 방송. **모르는 방송이어도 404가 아니라 200**(`state: unknown`)이다.",
    },
    ("/internal/streams/{streamId}/video-position", "get"): {
        "streamId": "방송을 가리키는 이름.",
        "messageTime": "채팅이 찍힌 시각. epoch ms(`1787529601000`) 또는 "
                       "ISO-8601(`2026-08-24T12:00:00Z`).\n\n"
                       "🔴 **`+09:00` 같은 오프셋을 쓸 때는 `+`를 `%2B`로 인코딩한다** — "
                       "쿼리에서 `+`는 공백으로 풀려 그대로 치면 400이다.",
        "channelId": "치지직 채널 번호. 방송 한 회를 못 찾을 때의 대체 경로다.",
    },
}

TAGS["chat-collector"] = [
    {"name": "내부 (서버 간 연동)", "description": "clip만 부른다. 사용자 JWT로는 통과할 수 없다."},
]


# ═══════════════════════════ 2026-09 추가분 — auth ═══════════════════════════
# POK-171 탈퇴 · POK-240 오디오 트랙 이름. 08-27 이후 구조만 자동으로 따라오고 설명이 비어 있던 자리다.

OPS["auth"].update({
    ("/api/auth/me", "delete"): (
        "회원 탈퇴",
        "**내 계정을 없앤다.** 회원 번호를 넘기지 않는다 — 토큰의 주인이 탈퇴한다.\n\n"
        "**한 번에 거둬 가는 것**: 로그인 세션(refresh 토큰) 전부 · 스트림키와 페어링 코드(OBS 송출이 즉시 막힌다) · "
        "치지직·유튜브 연동 · 편집자 초대와 위임(내가 준 것·받은 것 둘 다) · 오디오 트랙 이름 · 프로필 사진.\n\n"
        "**행은 지우지 않고 익명화한다** — 이메일과 구글 계정 연결이 지워지고, 이름은 「탈퇴한 사용자」가 된다. "
        "그래서 다른 화면에서 이 회원 번호를 조회하면 그 이름이 보인다. 내가 만든 편집본·영상 기록은 "
        "clip 서버에 그대로 남는다(auth가 다른 서버의 표를 건드리지 않는다 — ADR-022).\n\n"
        "🔴 **응답을 받은 직후부터 그 토큰은 전부 401이다.** 같은 access 토큰으로 다시 부르면 204가 아니라 401이 온다 — "
        "화면은 204를 받으면 저장해 둔 토큰을 지우고 로그인 화면으로 보내면 된다.\n\n"
        "**같은 구글 계정으로 다시 로그인하면 새 계정**이 생긴다. 탈퇴한 계정은 되살릴 수 없다.",
        [{"bearerAuth": []}], "내 정보", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/auth/me/audio-tracks", "get"): (
        "내 오디오 트랙 이름 보기",
        "편집 화면 오디오 탭에 「트랙 3」 대신 **「디스코드」**처럼 보이게 하는 이름표다. OBS에서 나눠 보낸 "
        "소리 트랙마다 스트리머가 이름을 붙인다.\n\n"
        "**칸은 늘 여섯이다**(트랙 1~6). 이름을 안 붙인 칸은 `null`이고, 한 번도 저장 안 했으면 여섯 다 `null`이다.",
        [{"bearerAuth": []}], "오디오 트랙 이름", {"401": UNAUTHORIZED_JWT},
    ),
    ("/api/auth/me/audio-tracks", "put"): (
        "내 오디오 트랙 이름 저장",
        "**여섯 칸을 통째로 덮는다**(PUT). 받은 것을 고쳐 그대로 돌려보내면 된다 — 요청과 응답이 같은 모양이다.\n\n"
        "- 칸 수가 **정확히 여섯**이어야 한다(아니면 `LABELS_SIZE`)\n"
        "- 이름을 지우려면 그 칸에 `null` 또는 빈 문자열을 넣는다\n"
        "- 앞뒤 공백은 서버가 자르고(전각 공백까지), **32자**까지다(이모지 1개 = 1자)\n"
        "- 줄바꿈·탭 같은 제어문자는 거절된다\n\n"
        "**응답은 저장된 결과**다 — 공백이 잘린 뒤의 값이 오므로 그것으로 화면을 덮어쓴다.",
        [{"bearerAuth": []}], "오디오 트랙 이름",
        {"400": key_err("칸 규칙에 안 맞는다. `reason` 으로 갈라 안내한다 — `LABELS_SIZE`(칸이 여섯이 아니다) · "
                        "`LABEL_TOO_LONG`(32자 초과) · `LABEL_INVALID`(제어문자).", "LABEL_TOO_LONG"),
         "401": UNAUTHORIZED_JWT},
    ),
    ("/api/streamers/{streamerUserId}/audio-tracks", "get"): (
        "스트리머의 오디오 트랙 이름 보기",
        "**편집자가 부르는 문이다.** 편집 화면은 내 방송이 아니라 스트리머의 방송을 여므로, 그 스트리머가 "
        "붙인 이름을 여기서 받는다. 스트리머 본인이 불러도 된다.\n\n"
        "**볼 수 있는 사람**: 그 스트리머 본인, 또는 그 스트리머에게 위임받은 편집자.\n\n"
        "모양은 `GET /api/auth/me/audio-tracks` 와 같다(여섯 칸, 빈 칸은 `null`).",
        [{"bearerAuth": []}], "오디오 트랙 이름",
        {"401": UNAUTHORIZED_JWT,
         "404": key_err("🔴 **없는 회원이든 볼 자격이 없든 똑같이 404다** — 갈라 주면 「그 번호가 회원인가」가 "
                        "새어 나간다. 화면은 「이름표 없음」으로 두고 트랙 번호를 그대로 보여 주면 된다.",
                        "STREAMER_NOT_FOUND")},
    ),
})

OK_DESC["auth"].update({
    ("/api/auth/me", "delete", "204"): "탈퇴 완료. 본문이 없다. **이 순간부터 그 토큰은 전부 401이다.**",
    ("/api/auth/me/audio-tracks", "get", "200"): "조회 성공. 칸은 늘 여섯이다.",
    ("/api/auth/me/audio-tracks", "put", "200"): "저장 성공. **공백을 자른 뒤의 값**을 돌려준다.",
    ("/api/streamers/{streamerUserId}/audio-tracks", "get", "200"): "조회 성공. 칸은 늘 여섯이다.",
})

PARAMS["auth"].update({
    ("/api/streamers/{streamerUserId}/audio-tracks", "get"): {
        "streamerUserId": "스트리머의 **회원 번호**. 방송 목록의 스트리머 번호, 위임 목록의 `streamerId` 와 같은 값이다.",
    },
})

FIELDS["auth"].update({
    "Labels": {
        "_": "오디오 트랙 이름표. **요청과 응답이 같은 모양**이다.",
        "labels": "트랙 1~6 의 이름. **길이는 늘 6**이고 `labels[0]` 이 트랙 1이다. 이름 없는 칸은 `null`. "
                  "트랙 번호는 편집본(`audio.tracks[].trackId`)의 1~5 와 같은 번호다.",
    },
})

TAGS["auth"].insert(2, {"name": "오디오 트랙 이름",
                        "description": "OBS가 나눠 보낸 소리 트랙(게임·마이크·디스코드…)에 스트리머가 붙이는 이름. "
                                       "편집 화면의 오디오 탭이 쓴다."})


# ═══════════════════════════ 2026-09 추가분 — clip ═══════════════════════════
# 편집본(POK-124) · 영상 만들기(POK-125) · 보관함(POK-243) · 완성 영상 주소(POK-247) · 유튜브 업로드(POK-220)
# · 재생 출입증(POK-122) · 되감기 채팅(POK-234) · 방송 중 목록(POK-218).

CLIP_400 = lambda desc, field: clip_err(desc, "invalid_request", {"field": field})
RECIPE_404 = clip_err("그런 방송이 없거나 볼 자격이 없거나, **그 방송에 그 번호의 편집본이 없다.** "
                      "🔴 셋을 구분해 주지 않는다(다른 방송의 편집본 번호를 넣어도 같은 404다).", "recipe_not_found")
CLIP_NOT_FOUND = clip_err("그런 방송이 없거나 볼 자격이 없거나, **그 방송에 그 번호의 영상이 없다.** "
                          "🔴 구분해 주지 않는다.", "clip_not_found")
RENDER_503 = clip_err("영상 만들기 줄(큐)이 꺼져 있다. **사용자 잘못이 아니다** — 「잠시 뒤 다시」.",
                      "render_unavailable")

RECIPE_BODY_DESC = (
    "**계약6 레시피 JSON 그대로**(편집기가 가진 상태를 통째로 보낸다). 규칙:\n\n"
    "- `schemaVersion` 은 **1**\n"
    "- `streamId` 는 **주소의 방송과 같아야** 한다\n"
    "- `cut` — 방송 절대시각(UTC epoch ms)의 `[inAtMs, outAtMs)`. 길이 **5초~180초**. "
    "**`cut` 을 `null` 로 보내면 템플릿**(구간 없는 편집 틀)으로 저장된다 — 템플릿은 영상 주문을 못 한다\n"
    "- `outputs` — 1개 이상. `outputId` 는 `[a-z0-9-]{1,32}` · 벌마다 유일 · `aspect` 는 `VERT_9_16`·`SQUARE_1_1` 중 하나이고 "
    "**같은 비율을 두 번 못 넣는다** · `crop` 은 정규화 좌표(좌상단 원점) `x,y ∈ [0,1)` · `w,h ≥ 0.05` · `x+w ≤ 1` · `y+h ≤ 1`\n"
    "- `audio.tracks` — 1개 이상. `trackId` 0 = 최종 믹스, 1~5 = 소스별 트랙. **0 과 1~5 를 같이 못 넣는다**(이중 산입) · "
    "`gain` 0.0~2.0 (1.0 = 원음)\n"
    "- `subtitles` — `null` 이면 자막 없음. `mode` 는 `BURN_AND_CC`(영상에 새김+srt)·`BURN_ONLY`·`CC_ONLY` · "
    "`segments` 는 방송 절대축 `[startAtMs, endAtMs)` 오름차순·겹침 금지(빈 배열 허용). 컷 밖 구간은 거절하지 않는다 — "
    "컷을 옮기면 다시 보인다\n\n"
    "본문은 **256KB** 까지. `Content-Type: application/json` 이 아니면 415.")

OPS["clip"].update({
    # ── 편집본 ──
    ("/api/clip/broadcasts/{streamId}/recipes", "post"): (
        "편집본 저장 (새로)",
        "**편집 화면의 「저장」.** 구간·화면 비율과 잘라내기·오디오·자막을 한 벌로 저장한다. 이것을 「레시피」라 부른다 — "
        "영상 파일이 아니라 **영상을 어떻게 만들지 적은 설계도**다. 영상은 이것으로 `…/renders` 를 불러야 만들어진다.\n\n"
        "**지우는 문은 없다**(영구 보존). 고치려면 `PUT …/recipes/{id}`.\n\n"
        "응답은 **201** 과 저장된 편집본이다. `recipeVersion` 은 1 로 시작한다.",
        [{"bearerAuth": []}], "편집본",
        {"400": CLIP_400("본문이 규칙에 안 맞는다. **`field` 가 어느 덩어리인지 알려준다** — `body`(JSON이 아니거나 비었거나 "
                         "256KB 초과) · `schemaVersion` · `streamId` · `cut` · `outputs` · `audio` · `subtitles`. "
                         "첫 번째로 어긋난 덩어리 하나만 온다.", "cut"),
         "401": CLIP_401, "404": CLIP_404, "503": CLIP_503_AUTH},
    ),
    ("/api/clip/broadcasts/{streamId}/recipes", "get"): (
        "편집본 목록 (한 방송)",
        "그 방송에 저장된 편집본 전부. **만든 순서(오래된 것 먼저)** 다. 페이지를 나누지 않는다.\n\n"
        "**누가 만든 것이든 다 온다** — 스트리머와 편집자가 같은 방송의 편집본을 같이 본다(`creatorId` 로 갈린다).\n\n"
        "여러 방송에 걸친 「내 편집본 전부」는 보관함(`GET /api/clip/library`)이다.",
        [{"bearerAuth": []}], "편집본", {"401": CLIP_401, "404": CLIP_404, "503": CLIP_503_AUTH},
    ),
    ("/api/clip/broadcasts/{streamId}/recipes/{id}", "get"): (
        "편집본 하나 보기",
        "편집 화면을 다시 열 때 부른다. `recipe` 가 **저장할 때 보낸 JSON 그대로** 돌아온다.",
        [{"bearerAuth": []}], "편집본", {"401": CLIP_401, "404": RECIPE_404, "503": CLIP_503_AUTH},
    ),
    ("/api/clip/broadcasts/{streamId}/recipes/{id}", "put"): (
        "편집본 고치기",
        "**통째로 갈아 끼운다**(부분 수정이 아니다). 성공하면 `recipeVersion` 이 **+1** 된다.\n\n"
        "🔴 **덮어쓰기 경고를 안 한다.** 두 사람이 같은 편집본을 동시에 고치면 줄을 서서 **둘 다 저장되고 나중 것이 남는다**"
        "(판이 두 번 오른다). 화면이 「누가 먼저 고쳤다」를 알아야 하면 응답의 `recipeVersion` 이 예상보다 크게 뛰었는지를 본다.\n\n"
        "이미 만든 영상은 **그 영상을 만든 판**을 기억한다 — 고쳐도 옛 영상이 바뀌지 않는다. 보관함에서는 "
        "「지금 판으로 만든 영상이 없다」가 되어 상태가 `editing` 으로 돌아간다.",
        [{"bearerAuth": []}], "편집본",
        {"400": CLIP_400("본문이 규칙에 안 맞는다. `field` 는 저장 문과 같다.", "outputs"),
         "401": CLIP_401, "404": RECIPE_404, "503": CLIP_503_AUTH},
    ),

    # ── 영상 만들기 ──
    ("/api/clip/broadcasts/{streamId}/recipes/{recipeId}/renders", "post"): (
        "영상 만들기 주문",
        "**편집본의 지금 판으로 영상을 만들어 달라고 주문한다.** 본문이 없다 — 무엇을 만들지는 편집본 번호가 말한다.\n\n"
        "- **201** 새 주문 · **200** 같은 편집본 같은 판의 주문이 이미 진행 중이다(그것을 돌려준다). "
        "**버튼을 두 번 눌러도 주문은 하나다**\n"
        "- 주문은 바로 끝나지 않는다. 응답의 `status` 는 `queued` 이고, 이후 `GET …/clips/{clipId}` 로 "
        "`rendering` → `rendered`(완성) 또는 `failed` 를 확인한다(진행률은 `progress.percent`)\n"
        "- 완성되면 `POST …/clips/{clipId}/file-access` 로 파일 주소를 받는다",
        [{"bearerAuth": []}], "영상 만들기·보관함",
        {"400": CLIP_400("**구간 없는 템플릿**이라 만들 수 없다(`field: cut`). 편집본에 구간을 넣고 저장한 뒤 다시 누른다.", "cut"),
         "401": CLIP_401, "404": RECIPE_404,
         "409": clip_err("그 구간의 방송 영상 조각이 **아직 다 안 올라왔다.** 방송 중이거나 막 끝났을 때 난다. "
                         "**잘라서 만들지 않는다** — 짧아진 영상이 조용히 나가는 것이 안 나가는 것보다 나쁘다. "
                         "몇 초 뒤 다시 누르면 된다.", "source_not_ready"),
         "422": clip_err("주문서가 너무 크다(200KB 초과) — 자막이 비정상적으로 많은 편집본이다.", "message_too_large"),
         "503": {"description": "`render_unavailable`(주문줄이 꺼짐) 또는 `authorization_unavailable`(자격 확인 불가). "
                                 "둘 다 「잠시 뒤 다시」다.",
                 "content": {"application/json": {"example": {"error": "render_unavailable"}}}}},
    ),
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}", "get"): (
        "만든 영상 상태 보기",
        "주문한 영상 하나의 지금 상태. **진행률을 보려고 몇 초마다 불러도 된다.**\n\n"
        "`status`: `queued`(줄 서는 중) → `rendering`(만드는 중, `progress.percent` 가 오른다) → `rendered`(완성) | `failed`(실패, "
        "`error` 에 사유).\n\n"
        "`upload` 에 가장 최근 유튜브 업로드가 붙어 온다(안 올렸으면 `null`).",
        [{"bearerAuth": []}], "영상 만들기·보관함", {"401": CLIP_401, "404": CLIP_NOT_FOUND, "503": CLIP_503_AUTH},
    ),
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}/file-access", "post"): (
        "완성 영상 파일 주소 받기",
        "**완성된 영상을 틀거나 내려받을 주소**를 준다. 창고(S3)가 비공개라 영상 기록의 `outputs[].s3Key` 로는 못 받는다 — "
        "이 문이 **60분짜리 미리서명 주소**를 만들어 준다.\n\n"
        "- 주소 하나가 곧 출입증이다: `expiresAt` 까지는 **로그인 없이 누구든** 그 주소로 받는다. 주소를 남에게 공유하지 않는다\n"
        "- 같은 주소를 `<video src>` 에 넣으면 재생, `<a href>` 로 열면 `fileName` 으로 내려받아진다\n"
        "- **POST 인 이유**: 부를 때마다 새 주소를 만든다. GET 이면 중간 캐시·브라우저 기록에 주소가 남는다. "
        "만료되면 다시 부르면 된다",
        [{"bearerAuth": []}], "영상 만들기·보관함",
        {"401": CLIP_401, "404": CLIP_NOT_FOUND,
         "409": clip_err("아직 완성되지 않았다(`queued`·`rendering`·`failed`).", "clip_not_rendered"),
         "503": {"description": "`render_unavailable`(창고 설정 없음) 또는 `authorization_unavailable`.",
                 "content": {"application/json": {"example": {"error": "render_unavailable"}}}}},
    ),

    # ── 보관함 ──
    ("/api/clip/library", "get"): (
        "보관함 목록",
        "**내가 볼 수 있는 모든 방송의 편집본을 한데 모은 목록**이다(방송을 고르지 않는다). 편집본 하나당 한 줄이고, "
        "그 원본 방송 요약과 **가장 최근 만든 영상**이 함께 붙어 온다.\n\n"
        "**새 편집본이 먼저** 온다. 다음 장은 `nextCursor` 를 그대로 되돌려 넣는다.\n\n"
        "편집본 본문(계약6 JSON)은 안 싣는다 — 무거워서다. 필요하면 `GET /api/clip/library/{recipeId}`.",
        [{"bearerAuth": []}], "영상 만들기·보관함",
        {"400": CLIP_400("요청 값이 잘못됐다 — `status`(모르는 값) · `limit`(0 이하) · `cursor`(우리가 준 표시가 아니다).",
                         "status"),
         "401": CLIP_401, "503": CLIP_503_AUTH},
    ),
    ("/api/clip/library/{recipeId}", "get"): (
        "보관함 상세",
        "목록 한 줄의 칸 전부 + **편집본 본문(`recipe`)**. 목록 줄과 같은 모양이라 화면이 같은 코드로 읽는다.\n\n"
        "방송 번호 없이 편집본 번호만으로 부른다(보관함은 방송을 고르지 않는다).",
        [{"bearerAuth": []}], "영상 만들기·보관함",
        {"401": CLIP_401,
         "404": clip_err("그런 편집본이 없거나 **볼 자격이 없다.** 🔴 구분해 주지 않는다.", "recipe_not_found"),
         "503": CLIP_503_AUTH},
    ),

    # ── 유튜브 업로드 ──
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}/uploads", "post"): (
        "유튜브에 올리기 주문",
        "**완성된 영상을 스트리머의 유튜브 채널에 비공개로 올려 달라고 주문한다.**\n\n"
        "- 올라가는 채널은 **그 방송의 스트리머 채널**이다(주문한 사람이 편집자여도). 스트리머가 유튜브 연동을 해 둬야 한다\n"
        "- **201** 새 주문 · **200** 같은 영상 같은 벌이 이미 올라가는 중이거나 올라갔다(그것을 돌려준다) — "
        "**두 번 눌러도 채널에 영상은 하나다**\n"
        "- 바로 끝나지 않는다. 결과는 `GET …/clips/{clipId}` 의 `upload`, 또는 보관함의 상태로 본다\n\n"
        "**상태**: `queued` → `uploading` → `uploaded`(끝, `videoId` 로 `https://youtu.be/{videoId}`) | "
        "`failed`(**채널에 영상이 없는 것이 확실** — 다시 주문할 수 있다) | "
        "🔴 `checking`(**올라갔는지 모른다** — 자동으로 다시 올리면 같은 영상이 둘 뜰 수 있어 멈춘다. "
        "스트리머가 채널에서 직접 확인해야 한다)",
        [{"bearerAuth": []}], "유튜브 업로드",
        {"400": CLIP_400("본문이 규칙에 안 맞는다 — `title`(비었거나 100자 초과, `<`·`>` 포함) · "
                         "`description`(5000바이트 초과, `<`·`>` 포함) · `outputId`(없는 벌이거나, 영상 벌이 여럿인데 안 줬다).",
                         "title"),
         "401": CLIP_401, "404": CLIP_NOT_FOUND,
         "409": clip_err("영상이 아직 완성되지 않았다.", "clip_not_rendered"),
         "503": {"description": "`upload_unavailable`(업로드 줄이 꺼짐) 또는 `authorization_unavailable`.",
                 "content": {"application/json": {"example": {"error": "upload_unavailable"}}}}},
    ),

    # ── 재생 출입증 ──
    ("/api/clip/broadcasts/{streamId}/playback-access", "post"): (
        "방송 영상 재생 출입증 받기",
        "**방송 영상(라이브·되감기·다시보기)을 플레이어가 받을 수 있게** 브라우저에 CloudFront 서명 쿠키를 붙여 준다. "
        "영상은 이 서버를 거치지 않고 CDN에서 바로 받는다.\n\n"
        "**응답 본문보다 `Set-Cookie` 헤더가 본체다** — 종류(`live`·`dvr`·`vod`)마다 쿠키 세 장, 모두 아홉 장이 붙는다. "
        "`HttpOnly` 라 자바스크립트로는 안 보이고, 브라우저가 영상 요청에 알아서 붙인다.\n\n"
        "🔴 **앱과 서버의 주소가 달라서, 이 문을 부를 때 `credentials: 'include'`(axios 는 `withCredentials: true`) 가 "
        "있어야 쿠키가 저장된다.** 빼먹으면 200 이 와도 영상 요청이 403 이 된다.\n\n"
        "출입증은 **60분** 짜리다(`expiresAt`). 만료 전에 같은 문을 다시 부르면 새 쿠키가 옛 것을 덮는다.",
        [{"bearerAuth": []}], "방송 영상 재생",
        {"401": CLIP_401, "404": CLIP_404,
         "503": {"description": "`playback_signing_unavailable`(서명 설정이 비었다 — 로컬 기본 상태) 또는 "
                                 "`authorization_unavailable`. **404 로 접지 않는다** — 설정이 채워지면 다시 누르면 된다.",
                 "content": {"application/json": {"example": {"error": "playback_signing_unavailable"}}}}},
    ),

    # ── 되감기 채팅 (중계) ──
    ("/api/clip/broadcasts/{streamId}/chat-messages", "get"): (
        "채팅·후원 목록 (한 구간)",
        "**되감기 화면이 영상 옆에 채팅을 띄우는 문.** `from`~`to` 구간에 들어온 채팅과 후원을 **한 목록에 섞어** 준다.\n\n"
        "clip 은 자격만 확인하고 **수집 서버(chat-collector)의 답을 그대로** 넘긴다. 그래서 응답 모양·400 사유 낱말"
        "(`missing`·`inverted`·`too_wide`…)이 수집 서버의 같은 창구와 글자까지 같다.\n\n"
        "🔴 **시각이 두 축이다.** 응답의 `time` 은 채팅이 **기록된** 시각이고, 영상 화면 위치는 "
        "**`time − appliedOffsetMs`** 로 구한다(방송이 몇 초 늦게 보이는 만큼 보정한 값이다). `from`·`to` 는 **화면 축**으로 준다.\n\n"
        "**한 번에 1시간까지**다. 라이브로 새로 오는 채팅은 SSE 통로(`…/events`)의 `chat`·`donation` 이벤트로 받는다.",
        [{"bearerAuth": []}], "되감기 채팅",
        {"400": {"description": "요청 값이 잘못됐다. 본문은 `{\"error\": 사유}` — `missing`(from·to 없음) · "
                                 "`unreadable`(시각 형식) · `out_of_range` · `inverted`(from ≥ to) · `too_wide`(1시간 초과) · "
                                 "`limit` · `kinds` · `cursor`.",
                 "content": {"application/json": {"example": {"error": "too_wide"}}}},
         "401": CLIP_401, "404": CLIP_404,
         "503": {"description": "`collector_unavailable`(수집 서버에 못 닿음) 또는 `authorization_unavailable`. "
                                 "🔴 **「채팅 0건」으로 접지 않는다** — 빈 목록이면 화면이 「그 구간엔 채팅이 없었다」로 단정한다.",
                 "content": {"application/json": {"example": {"error": "collector_unavailable"}}}}},
    ),
    ("/api/clip/broadcasts/{streamId}/chat-chart", "get"): (
        "채팅량 차트 (한 구간)",
        "되감기 화면 타임라인 위의 **채팅량 그래프**. 구간을 `bucket` 초 단위로 잘라 칸마다 채팅 수·후원 수를 센다. "
        "**빈 칸도 0 으로 들어 있다**(선을 끊김 없이 그리라고).\n\n"
        "목록 문과 같은 중계·같은 시각 규칙이다 — 칸의 `start` 는 기록 축이라 화면 위치는 `start − appliedOffsetMs`.",
        [{"bearerAuth": []}], "되감기 채팅",
        {"400": {"description": "`missing`·`unreadable`·`inverted`·`too_wide` · `bucket`(5·10·30·60 이 아니다) · "
                                 "`too_many_buckets`(점이 720 개를 넘는다).",
                 "content": {"application/json": {"example": {"error": "bucket"}}}},
         "401": CLIP_401, "404": CLIP_404,
         "503": {"description": "`collector_unavailable` 또는 `authorization_unavailable`.",
                 "content": {"application/json": {"example": {"error": "collector_unavailable"}}}}},
    ),
    ("/api/clip/broadcasts/{streamId}/broadcast-info", "get"): (
        "방송 정보 (제목·카테고리·시청자 수 추이)",
        "되감기 화면 위쪽의 **방송 제목·태그·카테고리**와 **시청자 수 그래프** 재료. 수집 서버가 1분마다 관측한 값이다.\n\n"
        "- `latest` — 가장 최근 관측. **`since` 와 무관하게** 늘 온다(구간이 비어도 제목은 보여야 해서). "
        "한 번도 관측 못 했으면 `null`\n"
        "- `series` — `since` 부터의 시청자 수 점들(최대 720 개). `since` 를 안 주면 최근 1시간\n\n"
        "**모르는 방송도 200** 이다(`latest: null`, `series: []`) — 방송이 켜진 직후엔 아직 관측 전이라서다.",
        [{"bearerAuth": []}], "되감기 채팅",
        {"400": {"description": "`since` 시각 형식이 틀렸다(`unreadable`·`out_of_range`).",
                 "content": {"application/json": {"example": {"error": "unreadable"}}}},
         "401": CLIP_401, "404": CLIP_404,
         "503": {"description": "`collector_unavailable` 또는 `authorization_unavailable`.",
                 "content": {"application/json": {"example": {"error": "collector_unavailable"}}}}},
    ),

    # ── 내부 창구 ──
    ("/internal/broadcasts/live", "get"): (
        "방송 중 목록 (내부 전용)",
        "**수집 서버가 재시작한 뒤 「지금 어느 방송에 붙어야 하나」를 묻는 문**이다. 명부에서 `live` 인 방송을 준다.\n\n"
        "- 요청 칸이 없다 → 400 도 없다. 거절은 401 하나\n"
        "- 자격 판정이 없다 — 부르는 쪽이 사람이 아니라 우리 서버다\n"
        "- 최대 **500 줄**. 넘으면 `truncated: true` — 개수 제한이라기보다 「명부가 이상하다」는 신호다"
        "(종료 알림을 놓친 방송이 `live` 로 남아 쌓이는 경우)",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."}},
    ),
    ("/internal/broadcasts/{streamId}/chat-events", "post"): (
        "라이브 채팅 밀어넣기 (내부 전용)",
        "**수집 서버가 방금 받은 채팅·후원·방송정보를 저장과 따로 바로 미는 문.** 받은 것을 그 방송의 SSE 연결에 뿌리고 "
        "**저장하지 않는다** — 정본은 수집 서버의 표다.\n\n"
        "- 그 방송을 보는 연결이 **없으면 DB 도 안 치고** `200 {accepted:0, dropped:0}` — 아무도 안 보는 방송의 채팅 유량이 "
        "clip 의 DB 부하가 되지 않게 하려는 것\n"
        "- 모르는 `kind` 는 400 이 아니라 건너뛰고 `dropped` 로 센다 — 수집 서버가 먼저 배포되는 날 채팅이 통째로 죽지 않게\n"
        "- 연결 큐가 차서 버린 것은 `dropped` 에 안 들어간다(연결마다 달라서)",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"400": CLIP_400("구조가 깨졌다 — `events`(없음·배열 아님·비었음·원소가 객체 아님) · `seq`(1 이상 정수가 아님) · "
                         "`kind`(비었음).", "events"),
         "401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."},
         "404": clip_err("보는 연결은 있는데 명부에 그 방송이 없다.", "broadcast_not_found")},
    ),
    ("/internal/jobs/{jobId}/events", "post"): (
        "렌더 일꾼 진행 보고 (내부 전용)",
        "**렌더 일꾼(workers/render)이 영상 만들기 진행을 보고하는 문**(계약1 4절). 같은 보고가 다시 와도 "
        "**그때 준 답을 그대로 다시 준다**(`eventId` 로 멱등).\n\n"
        "**`eventType` 다섯**: `STARTED`(시작 — 답으로 `executionToken` 을 받는다) · `PROGRESS` · `RETRY_SCHEDULED` · "
        "`SUCCEEDED`(`result` 에 산출물 목록) · `TERMINAL_FAILED`.\n\n"
        "**STARTED 의 답** `{proceed, executionToken, attemptOrdinal, isFinalAttempt}` — `proceed:false` 면 **일하지 말고 멈춘다**"
        "(이미 끝난 잡, 시도 상한 초과, 또는 같은 STARTED 의 재배달). 이후 보고에는 받은 `executionToken` 을 싣는다.\n\n"
        "**409 `SUPERSEDED`** — 토큰이 옛것이다. 다른 일꾼이 같은 잡을 새로 잡았으니 이 일꾼은 손을 뗀다. "
        "**409 `TERMINAL`** — 잡이 이미 끝났다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"400": {"description": "보고가 잘못됐다. 본문 `{\"reason\": ...}` — `INVALID_EVENT`(시작 전 보고 등) · "
                                 "`result_missing` · `unknown_output` · `key_outside_prefix` · `duplicate_video` · "
                                 "`unknown_kind` · `video_missing`(SUCCEEDED 의 산출물 검증). **재시도해도 같은 답이다.**",
                 "content": {"application/json": {"example": {"reason": "video_missing"}}}},
         "401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."},
         "404": clip_err("그런 잡이 없다.", "job_not_found"),
         "409": {"description": "`SUPERSEDED`(옛 토큰) 또는 `TERMINAL`(이미 끝남). 일꾼은 손을 뗀다.",
                 "content": {"application/json": {"example": {"reason": "SUPERSEDED"}}}}},
    ),
    ("/internal/uploads/{uploadId}/start", "post"): (
        "업로드 일꾼 — 주문 잡기 (내부 전용)",
        "**업로드 일꾼(workers/upload)이 줄에서 꺼낸 주문을 「잡았다」고 알린다.** 본문이 없다.\n\n"
        "답 `{proceed, status, attempt, sessionUri}`:\n"
        "- `proceed:false` — 이미 끝난 주문(`uploaded`·`failed`·`checking`). 같은 쪽지가 두 번 온 것이니 버린다\n"
        "- `sessionUri` 가 있으면 — **새로 만들지 말고 그 이어 올리기 주소에 「어디까지 받았나」부터 묻는다**. "
        "먼저 잡았던 일꾼이 주소를 받아 둔 것이다(이게 채널에 영상이 둘 뜨는 것을 막는다)",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."},
         "404": clip_err("그런 업로드 주문이 없다.", "upload_not_found")},
    ),
    ("/internal/uploads/{uploadId}/session", "post"): (
        "업로드 일꾼 — 이어 올리기 주소 기록 (내부 전용)",
        "**유튜브에서 받은 이어 올리기 주소를 적는다.** 🔴 **먼저 적힌 주소가 있으면 그것을 돌려준다** — 일꾼은 자기 주소를 "
        "버리고 돌려받은 주소로 올린다. 두 일꾼이 같은 주문을 동시에 잡아도 영상 바이트는 **한 주소로만** 가서 채널에 영상이 "
        "많아야 하나다.\n\n"
        "주소 자체가 올리기 권한이라 어떤 응답·로그에도 화면 쪽으로는 안 나간다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"400": CLIP_400("`sessionUri` 가 없거나 모양이 틀리다.", "sessionUri"),
         "401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."},
         "404": clip_err("그런 업로드 주문이 없다.", "upload_not_found"),
         "409": {"description": "`NOT_STARTED`(`start` 를 먼저 부르지 않았다) 또는 `TERMINAL`(이미 끝난 주문).",
                 "content": {"application/json": {"example": {"reason": "NOT_STARTED"}}}}},
    ),
    ("/internal/uploads/{uploadId}/result", "post"): (
        "업로드 일꾼 — 끝 보고 (내부 전용)",
        "`outcome` 셋: `UPLOADED`(`videoId` 필수) · `FAILED` · `CHECKING`(올라갔는지 모름). 같은 끝 보고가 다시 오면 200.\n\n"
        "🔴 **주소가 적힌 뒤에는 `FAILED` 를 받아도 `checking` 으로 닫는다.** 같은 주소로 다른 일꾼이 아직 올리는 중일 수 "
        "있어서다 — 자리를 비우면 다시 주문한 업로드와 늦게 끝난 쪽이 겹쳐 영상이 둘 뜬다. "
        "그리고 늦게 온 `UPLOADED` 는 `checking` 을 이긴다(정보가 더 많다).",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"400": CLIP_400("`outcome`(셋 중 하나가 아니다) · `videoId`(UPLOADED 인데 없거나 모양이 틀리다) · `errorCode`.",
                         "outcome"),
         "401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."},
         "404": clip_err("그런 업로드 주문이 없다.", "upload_not_found"),
         "409": {"description": "`NOT_STARTED` 또는 `TERMINAL`(다른 결과로 이미 끝났다).",
                 "content": {"application/json": {"example": {"reason": "TERMINAL"}}}}},
    ),
})

# SSE 통로에 채팅이 실리게 됐다(POK-234 PR-B). 기존 설명 뒤에 한 문단을 붙인다.
_sse = OPS["clip"][("/api/clip/broadcasts/{streamId}/events", "get")]
OPS["clip"][("/api/clip/broadcasts/{streamId}/events", "get")] = (
    _sse[0],
    _sse[1] + "\n\n**카드 말고도 흐르는 이벤트가 있다**(2026-09, POK-234): `chat` · `donation` · `broadcast-info`. "
              "이 셋은 `id` 에 수집 순번(`seq`)이 실리고 `data` 는 수집 서버가 준 JSON 그대로다 — "
              "되감기 목록 창구(`…/chat-messages`)의 `id` 와는 **다른 번호**라 둘을 짝지으면 안 된다. "
              "연결 직후에는 주석 한 줄(`: ok`)이 먼저 온다.",
    _sse[2], _sse[3], _sse[4])

OP_FIX["clip"] = {
    ("/api/clip/broadcasts/{streamId}/recipes", "post"): {
        "status": ("200", "201"),
        "body": {"required": True, "description": RECIPE_BODY_DESC,
                 "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RecipeDocument"}}}}},
    ("/api/clip/broadcasts/{streamId}/recipes/{id}", "put"): {
        "body": {"required": True, "description": RECIPE_BODY_DESC,
                 "content": {"application/json": {"schema": {"$ref": "#/components/schemas/RecipeDocument"}}}}},
    ("/api/clip/broadcasts/{streamId}/recipes/{recipeId}/renders", "post"): {"status": ("200", "201")},
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}/uploads", "post"): {"status": ("200", "201")},
    ("/internal/jobs/{jobId}/events", "post"): {
        "body": {"required": True, "description": "계약1 4절 봉투. 모르는 칸은 무시한다.",
                 "content": {"application/json": {"schema": {"type": "object", "properties": {
                     "eventId": {"type": "string", "format": "uuid", "description": "보고 한 통의 고유 번호. 같은 값이 다시 오면 저장된 답을 그대로 준다."},
                     "eventType": {"type": "string", "enum": ["STARTED", "PROGRESS", "RETRY_SCHEDULED", "SUCCEEDED", "TERMINAL_FAILED"]},
                     "occurredAt": {"type": "string", "description": "일꾼이 겪은 시각(ISO-8601)."},
                     "executionToken": {"type": "string", "format": "uuid", "description": "STARTED 답으로 받은 값. STARTED 와 준비 단계 실패에는 없다."},
                     "progressPercent": {"type": "integer", "description": "0~100. 같은 토큰 안에서 줄지 않는다."},
                     "progressStage": {"type": "string"},
                     "result": {"type": "array", "description": "SUCCEEDED 의 산출물. 칸마다 `outputId`·`kind`(`video`|`srt`)·`s3Key` — 벌마다 video 가 정확히 하나."},
                     "errorCode": {"type": "string"}, "errorMessage": {"type": "string"}},
                     "required": ["eventId", "eventType"]}}}},
        "ok": {"type": "object", "description": "STARTED 면 `{proceed, executionToken, attemptOrdinal, isFinalAttempt}`, 나머지는 빈 객체 `{}`."}},
    ("/internal/broadcasts/{streamId}/chat-events", "post"): {
        "body": {"required": True, "description": "수집 서버의 `ClipRelayClient` 가 정본이다.",
                 "content": {"application/json": {"schema": {"type": "object", "required": ["events"], "properties": {
                     "events": {"type": "array", "description": "한 묶음. 비면 400.", "items": {"type": "object", "required": ["seq", "kind"], "properties": {
                         "seq": {"type": "integer", "description": "수집 순번(1 이상). SSE 이벤트 `id` 로 그대로 나간다."},
                         "kind": {"type": "string", "description": "`chat`·`donation`·`broadcast-info`. 모르는 값은 건너뛴다."}},
                         "additionalProperties": True}}}}}}},
        "ok": {"type": "object", "properties": {"accepted": {"type": "integer", "description": "연결에 뿌리려고 넣은 수."},
                                                "dropped": {"type": "integer", "description": "모르는 kind 라 건너뛴 수."}}}},
    ("/internal/uploads/{uploadId}/start", "post"): {
        "ok": {"type": "object", "properties": {"proceed": {"type": "boolean"}, "status": {"type": "string"},
                                                "attempt": {"type": "integer", "description": "이 주문을 잡은 횟수(진단용)."},
                                                "sessionUri": {"type": "string", "description": "이미 적힌 이어 올리기 주소. 없으면 null."}}}},
    ("/internal/uploads/{uploadId}/session", "post"): {
        "ok": {"type": "object", "properties": {"sessionUri": {"type": "string", "description": "**이 주소로 올린다.** 먼저 적힌 것이 있으면 그것이다."}}}},
    ("/internal/uploads/{uploadId}/result", "post"): {
        "ok": {"type": "object", "description": "받은 뒤의 업로드 상태."}},
    ("/api/clip/broadcasts/{streamId}/playback-access", "post"): {
        "ok": {"type": "object", "properties": {
            "streamId": {"type": "string"},
            "expiresAt": {"type": "string", "description": "쿠키 만료 시각(ISO-8601). 이 전에 다시 부르면 갱신된다."},
            "resources": {"type": "array", "items": {"type": "string"},
                          "description": "쿠키가 여는 CDN 경로 셋(`…/live/{streamId}/*` · `…/dvr/…` · `…/vod/…`). 진단용이고 화면이 쓸 일은 없다."}}}},
    # 중계 문 셋 — MultiValueMap 이 'query' 뭉치 하나로 나온다. 실제로 넘기는 칸만 적는다(BroadcastChatController 의 허용 목록).
    ("/api/clip/broadcasts/{streamId}/chat-messages", "get"): {"params": [
        {"name": "from", "in": "query", "required": True, "schema": {"type": "string"}},
        {"name": "to", "in": "query", "required": True, "schema": {"type": "string"}},
        {"name": "limit", "in": "query", "schema": {"type": "integer"}},
        {"name": "cursor", "in": "query", "schema": {"type": "string"}},
        {"name": "kinds", "in": "query", "schema": {"type": "string"}}]},
    ("/api/clip/broadcasts/{streamId}/chat-chart", "get"): {"params": [
        {"name": "from", "in": "query", "required": True, "schema": {"type": "string"}},
        {"name": "to", "in": "query", "required": True, "schema": {"type": "string"}},
        {"name": "bucket", "in": "query", "schema": {"type": "integer", "enum": [5, 10, 30, 60]}}]},
    ("/api/clip/broadcasts/{streamId}/broadcast-info", "get"): {"params": [
        {"name": "since", "in": "query", "schema": {"type": "string"}}]},
}

_TIME_FMT = "epoch ms(`1787529601000`) 또는 ISO-8601(`2026-09-26T12:00:00Z`). 🔴 `+09:00` 을 쓰면 `+` 를 `%2B` 로 인코딩한다."
PARAMS["clip"].update({
    ("/api/clip/broadcasts/{streamId}/recipes", "post"): {"streamId": "방송 번호. **본문의 `streamId` 와 같아야** 한다."},
    ("/api/clip/broadcasts/{streamId}/recipes", "get"): {"streamId": "방송 번호."},
    ("/api/clip/broadcasts/{streamId}/recipes/{id}", "get"): {"streamId": "방송 번호.", "id": "편집본 번호(`RecipeSnapshot.id`)."},
    ("/api/clip/broadcasts/{streamId}/recipes/{id}", "put"): {"streamId": "방송 번호. **본문의 `streamId` 와 같아야** 한다.", "id": "고칠 편집본 번호."},
    ("/api/clip/broadcasts/{streamId}/recipes/{recipeId}/renders", "post"): {
        "streamId": "방송 번호.", "recipeId": "영상으로 만들 편집본 번호. **그 편집본의 지금 판**으로 만든다."},
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}", "get"): {"streamId": "방송 번호.", "clipId": "주문 응답의 `id`."},
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}/file-access", "post"): {"streamId": "방송 번호.", "clipId": "완성된 영상 번호."},
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}/uploads", "post"): {"streamId": "방송 번호.", "clipId": "올릴 완성 영상 번호."},
    ("/api/clip/broadcasts/{streamId}/playback-access", "post"): {"streamId": "볼 방송 번호. 출입증은 **그 방송 하나**만 연다."},
    ("/api/clip/library", "get"): {
        "status": "상태로 거르기. `editing`·`rendering`·`rendered`·`failed`·`uploading`·`checking`·`uploaded` 중 하나. "
                  "**소문자로만** 받는다. 안 주면 전부.",
        "limit": "한 장 개수. 안 주면 **20**, 최대 **100**. 0 이하는 400.",
        "cursor": "직전 응답의 `nextCursor` 를 **그대로**. 첫 장은 안 넣는다."},
    ("/api/clip/library/{recipeId}", "get"): {"recipeId": "편집본 번호(목록 줄의 `recipeId`)."},
    ("/api/clip/broadcasts/{streamId}/chat-messages", "get"): {
        "streamId": "방송 번호.",
        "from": "🔴 **필수.** 구간 시작(포함) — **화면 축**(영상 재생 위치의 절대시각). " + _TIME_FMT,
        "to": "🔴 **필수.** 구간 끝(미포함). `from` 보다 커야 하고 폭은 **1시간** 까지.",
        "limit": "한 장 개수. 안 주면 **200**, 최대 **500**(넘기면 잘라 준다). 0 이하는 400.",
        "cursor": "직전 응답의 `nextCursor` 를 **그대로**.",
        "kinds": "`chat`·`donation` 을 쉼표로. 안 주면 둘 다."},
    ("/api/clip/broadcasts/{streamId}/chat-chart", "get"): {
        "streamId": "방송 번호.",
        "from": "🔴 **필수.** 구간 시작 — 화면 축. " + _TIME_FMT,
        "to": "🔴 **필수.** 구간 끝(미포함). 폭 1시간까지.",
        "bucket": "칸 크기(초). **5·10·30·60** 중 하나. 안 주면 **10**."},
    ("/api/clip/broadcasts/{streamId}/broadcast-info", "get"): {
        "streamId": "방송 번호.",
        "since": "시청자 수 추이를 어디서부터 받을지. 안 주면 **지금부터 1시간 전**. " + _TIME_FMT},
    ("/internal/broadcasts/{streamId}/chat-events", "post"): {"streamId": "방송 번호."},
    ("/internal/jobs/{jobId}/events", "post"): {"jobId": "렌더 잡 번호(UUID). 주문서 봉투의 `jobId`."},
    ("/internal/uploads/{uploadId}/start", "post"): {"uploadId": "업로드 주문 번호. 주문서 봉투에 실려 온다."},
    ("/internal/uploads/{uploadId}/session", "post"): {"uploadId": "업로드 주문 번호."},
    ("/internal/uploads/{uploadId}/result", "post"): {"uploadId": "업로드 주문 번호."},
})

OK_DESC["clip"].update({
    ("/api/clip/broadcasts/{streamId}/recipes", "post", "201"): "저장됨. `recipeVersion` 1 로 시작한다.",
    ("/api/clip/broadcasts/{streamId}/recipes", "get", "200"): "조회 성공. 없으면 빈 배열.",
    ("/api/clip/broadcasts/{streamId}/recipes/{id}", "get", "200"): "조회 성공.",
    ("/api/clip/broadcasts/{streamId}/recipes/{id}", "put", "200"): "고쳐짐. `recipeVersion` 이 +1 됐다.",
    ("/api/clip/broadcasts/{streamId}/recipes/{recipeId}/renders", "post", "201"):
        "새 주문. **200 이면 같은 판의 주문이 이미 진행 중**이라 그것을 돌려준 것이다(둘 다 성공).",
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}", "get", "200"): "조회 성공.",
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}/file-access", "post", "200"): "주소 발급. `expiresAt` 까지 유효하다.",
    ("/api/clip/broadcasts/{streamId}/clips/{clipId}/uploads", "post", "201"):
        "새 주문. **200 이면 같은 영상의 업로드가 이미 있어** 그것을 돌려준 것이다(둘 다 성공).",
    ("/api/clip/broadcasts/{streamId}/playback-access", "post", "200"): "발급. **`Set-Cookie` 아홉 장이 본체다.**",
    ("/api/clip/library", "get", "200"): "조회 성공. 없으면 빈 배열.",
    ("/api/clip/library/{recipeId}", "get", "200"): "조회 성공.",
    ("/api/clip/broadcasts/{streamId}/chat-messages", "get", "200"): "조회 성공. 수집 서버의 답 그대로다.",
    ("/api/clip/broadcasts/{streamId}/chat-chart", "get", "200"): "조회 성공. 빈 칸도 0 으로 들어 있다.",
    ("/api/clip/broadcasts/{streamId}/broadcast-info", "get", "200"): "조회 성공. 모르는 방송도 200(`latest: null`).",
    ("/internal/broadcasts/live", "get", "200"): "조회 성공. 없으면 빈 배열.",
    ("/internal/broadcasts/{streamId}/chat-events", "post", "200"): "받음. 보는 연결이 없으면 0/0.",
    ("/internal/jobs/{jobId}/events", "post", "200"): "처리됨(또는 같은 보고의 재전송 — 그때 준 답 그대로).",
    ("/internal/uploads/{uploadId}/start", "post", "200"): "잡음(또는 `proceed:false`).",
    ("/internal/uploads/{uploadId}/session", "post", "200"): "기록됨. **돌려받은 `sessionUri` 로 올린다.**",
    ("/internal/uploads/{uploadId}/result", "post", "200"): "받음.",
})

FIELDS["clip"].update({
    "RecipeDocument": {
        "_": "**계약6 레시피 JSON.** 편집기가 보내는 모양이자 돌려받는 모양이다. 칸 이름을 한 글자도 바꾸지 않는다"
             "(편집기·렌더 일꾼과 셋이 같이 읽는다). 규칙은 저장 문의 본문 설명을 본다.",
        "schemaVersion": "지금은 **1** 뿐이다.",
        "streamId": "방송 번호. 주소의 방송과 같아야 한다.",
        "cut": "잘라낼 구간. **`null` 이면 템플릿**(구간 없는 틀 — 영상 주문 불가).",
        "outputs": "만들 영상 벌들(비율마다 하나). 하나 이상.",
        "audio": "켤 트랙과 음량.",
        "subtitles": "자막. `null` 이면 자막 없음."},
    "Cut": {"_": "구간 `[inAtMs, outAtMs)` — **방송 절대시각 UTC epoch ms**. 길이 5~180초.",
            "inAtMs": "시작(포함).", "outAtMs": "끝(미포함)."},
    "Output": {"_": "영상 한 벌.",
               "outputId": "벌 이름. `[a-z0-9-]{1,32}`, 한 편집본 안에서 유일. 완성 파일·업로드가 이 이름으로 가리킨다.",
               "aspect": "`VERT_9_16`(쇼츠 세로) 또는 `SQUARE_1_1`. 같은 비율을 두 벌 못 만든다.",
               "crop": "원본 화면에서 잘라낼 사각형."},
    "Crop": {"_": "**정규화 좌표**(원본 화면 폭·높이를 1로 본 비율). 좌상단이 (0,0).",
             "x": "왼쪽 끝 `[0,1)`.", "y": "위쪽 끝 `[0,1)`.",
             "w": "폭. 0.05 이상, `x+w ≤ 1`.", "h": "높이. 0.05 이상, `y+h ≤ 1`."},
    "Audio": {"_": "켤 오디오 트랙들.", "tracks": "하나 이상. `trackId` 0(믹스) 과 1~5(소스별)를 같이 못 넣는다."},
    "Track": {"_": "트랙 하나.",
              "trackId": "0 = 최종 믹스, 1~5 = OBS가 나눠 보낸 소스별 트랙(이름표는 auth 의 오디오 트랙 이름).",
              "gain": "음량 배율 0.0~2.0. **1.0 이 원음**."},
    "Subtitles": {"_": "자막.",
                  "mode": "`BURN_AND_CC`(영상에 새기고 srt 도) · `BURN_ONLY` · `CC_ONLY`(srt 만).",
                  "segments": "자막 줄들. 오름차순·겹침 금지. 빈 배열 허용."},
    "Segment": {"_": "자막 한 줄. 구간 `[startAtMs, endAtMs)` 은 **방송 절대축**(컷 기준이 아니다).",
                "startAtMs": "시작.", "endAtMs": "끝.", "text": "자막 글자."},
    "RecipeSnapshot": {
        "_": "저장된 편집본. `recipe` 는 계약6 JSON 그대로이고, 나머지는 서버가 붙인 칸이다.",
        "id": "편집본 번호.", "streamId": "방송 번호.",
        "creatorId": "처음 저장한 사람의 회원 번호(문자열). 고친 사람이 아니다.",
        "recipeVersion": "판 번호. 저장하면 1, **고칠 때마다 +1**. 영상은 「몇 판으로 만들었나」를 이것으로 기억한다.",
        "recipe": "편집본 본문(계약6).", "createdAt": "처음 저장한 시각.", "updatedAt": "마지막으로 고친 시각."},
    "RecipeListResponse": {"_": "한 방송의 편집본 목록.", "recipes": "만든 순서(오래된 것 먼저)."},
    "ClipSnapshot": {
        "_": "주문한 영상 하나(「완성 영상 한 벌」). 주문 문·상태 보기·보관함이 같은 모양을 쓴다.",
        "id": "영상 번호(`clipId`).", "streamId": "방송 번호.", "recipeId": "만든 편집본.",
        "recipeVersion": "**주문 시점의 편집본 판.** 뒤에 편집본을 고쳐도 이 영상은 그 판 그대로다.",
        "requestedBy": "주문한 사람의 회원 번호.",
        "status": "`queued`(줄 서는 중) · `rendering`(만드는 중) · `rendered`(완성) · `failed`.",
        "progress": "진행. 주문만 됐으면 0.",
        "outputs": "완성이면 산출물 목록(칸마다 `outputId`·`kind`(`video`|`srt`)·`s3Key`), 아니면 `null`. "
                   "🔴 **`s3Key` 로는 파일을 못 받는다**(창고 비공개) — `…/file-access` 로 주소를 받는다.",
        "error": "실패 사유. 성공이면 `null`.",
        "createdAt": "주문 시각.", "updatedAt": "마지막 상태 변경.",
        "upload": "가장 최근 유튜브 업로드. 안 올렸으면 `null`."},
    "ClipProgress": {"_": "렌더 일꾼이 마지막으로 보고한 진행.",
                     "percent": "0~100. **다시 시도하면 0으로 돌아간다.**",
                     "stage": "일꾼이 붙인 단계 이름(표시용).",
                     "attempt": "몇 번째 시도인가(1부터). 3이 마지막.",
                     "jobId": "렌더 잡 번호. 진단용."},
    "ClipError": {"_": "영상 만들기 실패 사유(계약1).", "code": "사유 코드.", "message": "사람이 읽을 설명."},
    "ClipFileAccess": {"_": "완성 영상 파일 주소들. **주소 하나가 곧 출입증**이다.",
                       "clipId": "영상 번호.", "expiresAt": "주소 만료 시각(발급 후 60분).",
                       "files": "파일들. 일꾼이 보고한 순서 그대로."},
    "File": {"_": "파일 하나.", "outputId": "어느 벌의 파일인가.", "kind": "`video` 또는 `srt`(자막).",
             "fileName": "내려받을 때 이름.",
             "url": "미리서명 주소. `<video src>` 로 재생, `<a href>` 로 내려받기. 만료되면 다시 발급받는다."},
    "UploadRequest": {"_": "업로드 주문 본문. **본문 없이 불러도 된다**(제목이 필수라 400이 나지만).",
                      "title": "🔴 **필수.** 유튜브 제목. 앞뒤 공백을 걷고 1~100자, `<`·`>` 금지.",
                      "description": "유튜브 설명. 5000바이트까지, `<`·`>` 금지. 없으면 빈 설명.",
                      "outputId": "올릴 벌. **영상 벌이 하나면 생략 가능**, 여럿이면 필수."},
    "UploadSnapshot": {
        "_": "업로드 한 줄. 🔴 이어 올리기 주소는 **싣지 않는다** — 그 주소 자체가 올리기 권한이다.",
        "id": "업로드 번호.", "clipId": "올린 영상.", "outputId": "올린 벌.", "title": "유튜브 제목.",
        "status": "`queued` · `uploading` · `uploaded` · `failed`(채널에 없음이 확실 — 다시 주문 가능) · "
                  "🔴 `checking`(올라갔는지 모름 — **사람이 채널에서 확인**. 자동으로 다시 안 올린다).",
        "videoId": "올렸을 때만. 주소는 `https://youtu.be/{videoId}`.",
        "error": "실패 사유. 아니면 `null`.", "requestedBy": "주문한 사람. 채널 주인(스트리머)과 다를 수 있다.",
        "createdAt": "주문 시각.", "updatedAt": "마지막 상태 변경."},
    "UploadError": {"_": "업로드 실패 사유.", "code": "사유 코드(예: 한도 초과 `QUOTA_EXCEEDED`).", "message": "설명."},
    "SessionBody": {"_": "이어 올리기 주소 기록 본문.", "sessionUri": "유튜브가 준 이어 올리기 주소."},
    "ResultBody": {"_": "끝 보고 본문.", "outcome": "`UPLOADED` · `FAILED` · `CHECKING`.",
                   "videoId": "UPLOADED 면 필수.", "errorCode": "실패 사유 코드.", "errorMessage": "실패 설명. 주소 모양 글자는 서버가 지운다."},
    "LibraryEntry": {
        "_": "보관함 한 줄 = 편집본 하나 + 원본 방송 요약 + 가장 최근 영상. 편집본 본문은 없다(상세에서 준다).",
        "recipeId": "편집본 번호.", "streamId": "원본 방송.", "creatorId": "만든 사람.",
        "recipeVersion": "편집본의 지금 판.", "cut": "구간. 템플릿이면 `null`.",
        "status": "**파생 상태**(어느 표의 칸도 아니다): `editing`(지금 판으로 만든 영상 없음) · `rendering` · "
                  "`rendered`(완성 — 화면의 「업로드 대기」) · `failed` · `uploading` · `checking` · `uploaded`. "
                  "업로드가 `failed` 면 `rendered` 로 돌아간다(다시 올릴 수 있다).",
        "broadcast": "원본 방송 요약.",
        "latestClip": "가장 최근 만든 영상. 🔴 그 `recipeVersion` 이 이 줄의 것과 **다를 수 있다** — 그때 상태가 `editing` 이다. "
                      "안 만들었으면 `null`.",
        "createdAt": "편집본을 처음 저장한 시각.", "updatedAt": "편집본을 마지막으로 고친 시각."},
    "LibraryDetail": {
        "_": "보관함 상세 — 목록 줄의 칸 전부 + `recipe`.",
        "recipeId": "편집본 번호.", "streamId": "원본 방송.", "creatorId": "만든 사람.",
        "recipeVersion": "지금 판.", "cut": "구간.", "status": "목록 줄과 같은 파생 상태.",
        "broadcast": "원본 방송 요약.", "latestClip": "가장 최근 영상.",
        "createdAt": "처음 저장.", "updatedAt": "마지막 수정.", "recipe": "편집본 본문(계약6)."},
    "BroadcastSummary": {"_": "원본 방송 요약. 방송 목록 줄과 칸 이름이 같다.",
                         "status": "`live` · `ended` · `vod_ready`.", "startedAt": "시작. `null` 일 수 있다.",
                         "endedAt": "종료.",
                         "vodExpiresAt": "원본 다시보기 만료 시각 — 화면의 「원본 만료 D-day」 재료."},
    "LibraryListResponse": {"_": "보관함 한 장.", "items": "새 편집본이 먼저.",
                            "nextCursor": "다음 장 표시. 그대로 되돌려 넣는다. 마지막 장이면 `null`."},
    "LiveBroadcastsResponse": {"_": "방송 중 목록(수집 서버용).", "broadcasts": "`live` 인 방송들.",
                               "truncated": "500 줄을 넘어 잘렸으면 `true` — 명부 이상 신호."},
    "LiveBroadcastsItem": {"_": "방송 중 한 줄.", "streamId": "방송 번호.",
                           "streamerId": "스트리머 회원 번호 — **문자열**이다(명부 칸이 문자열이라서).",
                           "startedAt": "방송 시작. 운영 경로로는 `null` 이 안 나오지만 오면 지우지 않고 `null` 로 싣는다."},
})

SCHEMA_ALIAS["clip"] = {"Progress": "ClipProgress"}

TAGS["clip"][1:1] = [
    {"name": "편집본", "description": "편집 화면의 저장 단위(「레시피」). 영상 파일이 아니라 **영상을 어떻게 만들지 적은 설계도**다 — "
                                    "구간·화면 비율·오디오·자막. 계약6 JSON 그대로 주고받는다."},
    {"name": "영상 만들기·보관함", "description": "편집본으로 영상을 주문하고, 상태를 보고, 완성 파일 주소를 받는다. "
                                         "보관함은 여러 방송에 걸친 편집본·영상을 한데 모은 목록이다."},
    {"name": "유튜브 업로드", "description": "완성 영상을 스트리머 채널에 비공개로 올린다. **두 번 눌러도 영상은 하나다.**"},
    {"name": "방송 영상 재생", "description": "라이브·되감기·다시보기를 CDN에서 받게 하는 출입증(서명 쿠키)."},
    {"name": "되감기 채팅", "description": "되감기 화면의 채팅 목록·채팅량 차트·방송 정보. clip 이 자격만 보고 수집 서버 답을 그대로 넘긴다."},
]


# ═══════════════════════════ 2026-09 추가분 — chat-collector ═══════════════════════════
# POK-234 범위 창구 셋. clip 의 되감기 채팅 문 셋이 이것을 그대로 중계한다.

_COL_TIME = "epoch ms 또는 ISO-8601. `+09:00` 은 `+` 를 `%2B` 로 인코딩한다."
_COL_400 = lambda reasons, ex: {
    "description": "요청 값이 잘못됐다. 본문 `{\"error\": 사유}` — " + reasons,
    "content": {"application/json": {"example": {"error": ex}}}}
_COL_401 = {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."}

OPS["chat-collector"].update({
    ("/internal/streams/{streamId}/chat-messages", "get"): (
        "채팅·후원 목록 (내부 전용)",
        "**한 구간의 채팅과 후원을 한 목록에 섞어** 준다. 부르는 쪽은 clip 이고 **자격 판정은 clip 이 한다.**\n\n"
        "🔴 **시각이 두 축이다.** `from`·`to` 는 **화면 축**(영상 재생 위치의 절대시각)으로 받고, 표를 찾을 때 여기에 "
        "보정값(`appliedOffsetMs`)을 더한다. 응답 줄의 `time` 은 **표에 찍힌 원본 시각**이라, 화면 위치는 "
        "`time − appliedOffsetMs` 다.\n\n"
        "**DB 가 죽으면 500 을 그대로 낸다** — 빈 목록으로 삼키면 「그 구간에 채팅이 없었다」로 읽힌다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"400": _COL_400("`missing` · `unreadable` · `out_of_range` · `inverted` · `too_wide`(1시간 초과) · "
                         "`limit` · `kinds` · `cursor`.", "inverted"),
         "401": _COL_401},
    ),
    ("/internal/streams/{streamId}/chat-chart", "get"): (
        "채팅량 차트 (내부 전용)",
        "구간을 `bucket` 초로 잘라 칸마다 채팅 수·후원 수를 센다. **빈 칸도 0 으로 들어 있다.** "
        "시각 규칙은 목록 창구와 같다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"400": _COL_400("`missing` · `unreadable` · `out_of_range` · `inverted` · `too_wide` · "
                         "`bucket`(5·10·30·60 아님) · `too_many_buckets`(720 초과).", "bucket"),
         "401": _COL_401},
    ),
    ("/internal/streams/{streamId}/broadcast-info", "get"): (
        "방송 정보 (내부 전용)",
        "1분마다 관측한 **제목·태그·카테고리·시청자 수.** `latest` 는 가장 최근 관측(구간과 무관), `series` 는 "
        "`since` 부터의 시청자 수 점(최대 720).\n\n"
        "**모르는 방송도 200** — `latest: null`, `series: []`. 방송 직후에는 늘 관측 전이라 404 로 가르면 안 된다.",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"400": _COL_400("`since` 형식(`unreadable`·`out_of_range`).", "unreadable"), "401": _COL_401},
    ),
})

OK_DESC["chat-collector"].update({
    ("/internal/streams/{streamId}/chat-messages", "get", "200"): "조회 성공. 없으면 빈 배열.",
    ("/internal/streams/{streamId}/chat-chart", "get", "200"): "조회 성공.",
    ("/internal/streams/{streamId}/broadcast-info", "get", "200"): "조회 성공. 모르는 방송도 200.",
})

PARAMS["chat-collector"].update({
    ("/internal/streams/{streamId}/chat-messages", "get"): {
        "streamId": "방송 번호.",
        "from": "🔴 **필수.** 구간 시작(포함) — 화면 축. " + _COL_TIME,
        "to": "🔴 **필수.** 구간 끝(미포함). 폭 1시간까지.",
        "limit": "안 주면 200, 최대 500(넘기면 잘라 준다). 0 이하·숫자 아님은 400.",
        "cursor": "직전 응답의 `nextCursor` 그대로.",
        "kinds": "`chat`·`donation` 을 쉼표로. 안 주면 둘 다.",
        "channelId": "보정값을 고르는 채널. **clip 은 넘기지 않는다**(브라우저가 정하게 두지 않으려고) — 없으면 세션 정보에서 찾는다."},
    ("/internal/streams/{streamId}/chat-chart", "get"): {
        "streamId": "방송 번호.",
        "from": "🔴 **필수.** 구간 시작 — 화면 축. " + _COL_TIME,
        "to": "🔴 **필수.** 구간 끝(미포함).",
        "bucket": "칸 크기(초) 5·10·30·60. 안 주면 10.",
        "channelId": "목록 창구와 같다. clip 은 넘기지 않는다."},
    ("/internal/streams/{streamId}/broadcast-info", "get"): {
        "streamId": "방송 번호.",
        "since": "추이를 어디서부터. 안 주면 지금부터 1시간 전. " + _COL_TIME},
})

FIELDS["chat-collector"].update({
    "ChatWindowPage": {"_": "채팅·후원 목록 한 장.", "items": "시각 순.",
                       "nextCursor": "다음 장 표시. **마지막 장이면 `null`**(빈 문자열이 아니다).",
                       "appliedOffsetMs": "이 답에 실제로 쓴 보정값(ms). 화면 위치 = `time − appliedOffsetMs`. 늘 실린다."},
    "ChatWindowItem": {
        "_": "한 줄. 채팅과 후원이 섞여 나가므로 칸이 합집합이다(해당 없는 칸은 `null`).",
        "kind": "`chat` 또는 `donation`.",
        "id": "그 표의 번호 — 채팅과 후원이 **각자 1부터** 센다. `kind` 와 짝지어야 유일하다. "
              "🔴 SSE 로 오는 `seq` 와 **다른 번호**다.",
        "time": "**표에 찍힌 원본 시각.** 화면 위치는 `time − appliedOffsetMs`.",
        "timeBasis": "`message`(치지직이 찍은 시각) 또는 `received`(우리 서버가 받은 시각). "
                     "**후원은 치지직이 시각을 안 줘서 늘 `received`** — 채팅 사이에 몇 초 어긋나 끼일 수 있다.",
        "nickname": "보낸 사람 닉네임. 옛 줄(닉네임 저장 전)은 `null`.",
        "senderChannelId": "보낸 사람의 치지직 채널 번호.",
        "role": "치지직 역할 코드. 치지직이 안 보내는 경우가 많아 `null` 일 수 있다.",
        "text": "채팅 글자 또는 후원 메시지.",
        "amount": "후원 금액(원). 채팅이거나 숫자로 못 읽으면 `null`.",
        "donationType": "후원 종류. 채팅이면 `null`."},
    "ChatChartPage": {"_": "채팅량 차트 한 장.", "bucketSeconds": "칸 크기(초).",
                      "buckets": "칸들. 빈 칸도 0 으로 들어 있다.",
                      "appliedOffsetMs": "목록 창구와 같은 뜻."},
    "ChartBucket": {"_": "칸 하나.", "start": "칸 시작 — **표 축**이다. 화면 위치는 `start − appliedOffsetMs`.",
                    "chats": "채팅 수.", "donations": "후원 수."},
    "BroadcastInfoResponse": {"_": "방송 정보.", "latest": "가장 최근 관측. 없으면 `null`. `since` 와 무관하다.",
                              "series": "`since` 부터의 시청자 수 점들(최대 720)."},
    "Latest": {"_": "가장 최근에 관측한 방송 정보.", "title": "방송 제목.", "tags": "방송 태그들.",
               "category": "카테고리(게임 등).", "viewers": "그때 시청자 수.", "observedAt": "관측 시각."},
    "Point": {"_": "시청자 수 점 하나.", "observedAt": "관측 시각.", "viewers": "시청자 수. 못 읽었으면 `null`."},
})

SCHEMA_ALIAS["chat-collector"] = {"Response": "BroadcastInfoResponse"}


# 프레임워크 내부 타입이 스키마로 새어 나오는 자리들. 그대로 두면 Jackson의 JsonNode가
# 27개 필드(`isArray`·`isFloat`·`nodeType`…)로 펼쳐져 문서를 통째로 덮는다 — 읽는 사람에게
# 아무 뜻이 없고, 정작 「자유 형식 JSON」이라는 사실은 어디에도 안 적힌다.
INLINE_REPLACEMENT = {
    "JsonNode": {"type": "object", "additionalProperties": True,
                 "description": "자유 형식 JSON. 구조를 고정하지 않는다 — 판별기가 넣는 근거라 "
                                "종류마다 모양이 다르다."},
    "SseEmitter": {"type": "string",
                   "description": "**JSON 응답이 아니다.** `text/event-stream`으로 이벤트가 "
                                  "계속 흘러온다 — 각 이벤트의 `data`가 카드 한 장(JumpCardSnapshot)이다."},
}


def inline_framework_types(doc):
    """내부 타입 참조를 뜻이 통하는 형태로 바꾸고 스키마 목록에서 뺀다."""
    schemas = doc.get("components", {}).get("schemas", {})
    replaced = []
    for name, body in INLINE_REPLACEMENT.items():
        if name not in schemas:
            continue
        text = json.dumps(doc, ensure_ascii=False)
        # $ref 한 칸을 통째로 치환한다 — {"$ref": "#/components/schemas/JsonNode"} → 실제 정의
        text = text.replace(json.dumps({"$ref": f"#/components/schemas/{name}"}, ensure_ascii=False),
                            json.dumps(body, ensure_ascii=False))
        doc.clear()
        doc.update(json.loads(text))
        doc["components"]["schemas"].pop(name, None)
        replaced.append(name)
    return replaced


def shorten_schema_names(doc):
    """FQN 스키마 키를 읽기 좋은 이름으로 되돌린다.

    extract.sh가 `-Dspringdoc.use-fqn=true`로 뽑는 이유는 **이름 충돌 때문**이다 —
    auth의 chzzk와 youtube가 같은 이름의 DTO를 각자 갖고 있어서, 끄면 한쪽이 다른
    쪽을 조용히 덮어쓴다(2026-08-25에 치지직의 EXPIRED 상태가 그렇게 사라졌다).

    그렇다고 FQN을 그대로 화면에 내보내면 못 읽는다. 그래서 여기서 되돌린다:
      - 클래스 이름이 문서에서 유일하면  → 그 이름 그대로 (`GoogleLoginRequest`)
      - 겹치면 → 패키지의 기능 조각을 앞에 붙인다 (`ChzzkLinkRequest`·`YoutubeLinkRequest`)
    """
    schemas = doc.get("components", {}).get("schemas", {})
    # 스키마가 하나도 없는 서버가 있다 — chat-detector는 코드는 있지만
    # 부르는 쪽이라 노출하는 API도 DTO도 없다.
    # 여기서 안 막으면 아래 doc["components"]["schemas"]가 KeyError로 터지고
    # **배포 전체가 죽는다** — 2026-08-25에 실제로 그랬다.
    if not schemas:
        return {}
    by_simple = {}
    for fq in schemas:
        by_simple.setdefault(fq.rsplit(".", 1)[-1], []).append(fq)

    rename = {}
    for simple, fqs in by_simple.items():
        if len(fqs) == 1:
            rename[fqs[0]] = simple
            continue
        for fq in fqs:
            parts = fq.split(".")
            outer = parts[-2]
            if outer[:1].isupper():
                # 중첩 record다(ClipSnapshot.Error · LiveBroadcastsResponse.Item). 바깥 클래스 이름으로 가른다 —
                # 패키지로 가르면 **같은 패키지의 두 바깥 클래스**가 같은 이름이 된다(아래 🔴).
                base = outer
                for suffix in ("Response", "Snapshot"):
                    if base.endswith(suffix) and base != suffix:
                        base = base[: -len(suffix)]
                        break
                rename[fq] = base + simple
            else:
                # com.pokeclip.auth.chzzk.api.dto.LinkRequest → 'chzzk'
                hint = parts[parts.index("api") - 1] if "api" in parts else ""
                rename[fq] = (hint[:1].upper() + hint[1:] + simple) if hint else simple

    # 🔴 줄인 이름이 겹치면 아래 dict 가 한쪽을 **조용히 덮어쓴다.** 2026-09-26 에 실제로 그랬다 —
    # 방송 목록의 Item 과 방송 중 목록의 Item 이 둘 다 broadcast/api 에 있어 패키지 힌트가 같았고,
    # 둘 다 BroadcastItem 이 되어 /internal/broadcasts/live 문서가 **남의 칸 여섯**을 보여 줬다.
    # ClipSnapshot.Error 와 UploadSnapshot.Error 도 둘 다 Error 가 됐다(패키지에 api 가 없어 힌트가 비었다).
    # 08-25 의 EXPIRED 사라짐과 같은 병이 「줄이는 단계」에서 다시 난 것이라, 여기서는 **죽인다** —
    # 틀린 문서를 조용히 내보내는 것보다 배포가 멈추는 편이 낫다.
    seen = {}
    for fq, short in rename.items():
        if short in seen:
            raise SystemExit(f"스키마 이름 충돌: {seen[short]} 과 {fq} 가 둘 다 {short} 가 된다 — "
                             "shorten_schema_names 의 가르는 규칙을 고친다")
        seen[short] = fq

    # 이름만 바꾸면 $ref가 끊긴다. 문서 전체를 문자열로 치환한다 —
    # 긴 이름부터 바꿔야 짧은 이름이 긴 이름의 일부를 먼저 먹지 않는다.
    text = json.dumps(doc, ensure_ascii=False)
    for fq in sorted(rename, key=len, reverse=True):
        text = text.replace(f"#/components/schemas/{fq}", f"#/components/schemas/{rename[fq]}")
    doc.clear()
    doc.update(json.loads(text))
    doc["components"]["schemas"] = {rename.get(k, k): v
                                    for k, v in doc["components"]["schemas"].items()}
    return rename


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


# 부르는 쪽이 서버마다 다르다. 여기가 「누가 이 문을 쓰나」를 적는 유일한 자리다.
INTERNAL_CALLER = {
    "auth": "Media·clip·chat-collector·업로드 워커가 쓴다.",
    "clip": "판별기(chat-detector)가 쓴다.",
    "chat-collector": "clip이 쓴다.",
}


def report_unmatched(doc, server):
    """적어 뒀는데 **어디에도 안 붙은** 설명을 찍는다.

    springdoc이 스키마 이름을 클래스 이름으로 짓기 때문에, 새 DTO 하나가 들어오는 것만으로
    기존 이름이 갈릴 수 있다(`Item` → `SegmentItem`·`BroadcastItem`). 그러면 여기 적어 둔
    설명이 조용히 안 붙는다 — 문서는 멀쩡해 보이는데 그 칸만 비어 나간다.
    경로가 없어지거나 이름이 바뀐 경우도 같다.

    죽이지 않고 경고만 하는 이유: 문서를 배포하는 쪽이 코드보다 늦게 따라가는 것이 정상이고,
    한 칸 때문에 전체 배포를 막으면 나머지 최신 내용까지 못 나간다.
    """
    paths = doc.get("paths", {})
    schemas = doc.get("components", {}).get("schemas", {})
    lost = []
    for (path, method) in OPS.get(server, {}):
        if paths.get(path, {}).get(method) is None:
            lost.append(f"OPS {method.upper()} {path}")
    for (path, method) in PARAMS.get(server, {}):
        if paths.get(path, {}).get(method) is None:
            lost.append(f"PARAMS {method.upper()} {path}")
    for (path, method, code) in OK_DESC.get(server, {}):
        if paths.get(path, {}).get(method, {}).get("responses", {}).get(code) is None:
            lost.append(f"OK_DESC {method.upper()} {path} → {code}")
    for name, fields in FIELDS.get(server, {}).items():
        schema = schemas.get(name)
        if schema is None:
            lost.append(f"FIELDS 스키마 {name}")
            continue
        for field in fields:
            if field != "_" and field not in schema.get("properties", {}):
                lost.append(f"FIELDS {name}.{field}")
    if lost:
        print(f"  ⚠ {server}: 적어 뒀는데 안 붙은 설명 {len(lost)}개 "
              f"— 이름이 바뀌었거나 없어진 자리다")
        for item in lost:
            print(f"      {item}")
    return lost


def apply_fixes(doc, server):
    schemas = doc.setdefault("components", {}).setdefault("schemas", {})
    for old, new in SCHEMA_ALIAS.get(server, {}).items():
        if old in schemas and new not in schemas:
            text = json.dumps(doc, ensure_ascii=False).replace(
                f'"#/components/schemas/{old}"', f'"#/components/schemas/{new}"')
            doc.clear(); doc.update(json.loads(text))
            doc["components"]["schemas"][new] = doc["components"]["schemas"].pop(old)
    for (path, method), fix in OP_FIX.get(server, {}).items():
        op = doc.get("paths", {}).get(path, {}).get(method)
        if op is None:
            continue
        if "body" in fix:
            op["requestBody"] = fix["body"]
        if "params" in fix:
            keep = [p for p in op.get("parameters", []) if p.get("in") == "path"]
            op["parameters"] = keep + fix["params"]
        responses = op.setdefault("responses", {})
        if "ok" in fix and "200" in responses:
            responses["200"]["content"] = {"application/json": {"schema": fix["ok"]}}
        if "status" in fix:
            frm, to = fix["status"]
            if frm in responses and to not in responses:
                responses[to] = responses.pop(frm)


def enrich(doc, server):
    apply_fixes(doc, server)
    schemes = {}
    # 사람 토큰을 쓰는 문이 하나라도 있으면 bearerAuth를 싣는다.
    if any(not p.startswith("/internal") for p in doc.get("paths", {})):
        schemes["bearerAuth"] = {
            "type": "http", "scheme": "bearer", "bearerFormat": "JWT",
            "description": "로그인으로 받은 access 토큰. 30분 만료."}
    if any(p.startswith("/internal") for p in doc.get("paths", {})):
        schemes["internalToken"] = {
            "type": "apiKey", "in": "header", "name": "X-Internal-Token",
            "description": INTERNAL_CALLER.get(server, "다른 서버가 쓴다.")
                           + " 배포 환경마다 값을 맞춘다."}
    if schemes:
        doc.setdefault("components", {})["securitySchemes"] = schemes
    for (path, method), (summary, desc, sec, tag, extra) in OPS.get(server, {}).items():
        op = doc.get("paths", {}).get(path, {}).get(method)
        if op is None:
            continue
        op["summary"] = summary
        op["description"] = desc
        op["security"] = sec
        op["tags"] = [tag]
        op.setdefault("responses", {}).update(extra)
    for (path, method, code), text in OK_DESC.get(server, {}).items():
        resp = doc.get("paths", {}).get(path, {}).get(method, {}).get("responses", {}).get(code)
        if resp is not None:
            resp["description"] = text
    # springdoc은 @ResponseStatus(NO_CONTENT)를 못 읽고 200으로 적는다.
    for path, method, text in NO_CONTENT.get(server, []) + [
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
    for (path, method), specs in PARAMS.get(server, {}).items():
        op = doc.get("paths", {}).get(path, {}).get(method)
        if op is None:
            continue
        for param in op.get("parameters", []):
            text = specs.get(param.get("name"))
            if text:
                param["description"] = text

    for name, spec in FIELDS.get(server, {}).items():
        schema = doc.get("components", {}).get("schemas", {}).get(name)
        if schema is None:
            continue
        schema["description"] = spec["_"]
        for field, text in spec.items():
            if field != "_" and field in schema.get("properties", {}):
                schema["properties"][field]["description"] = text
    if TAGS.get(server):
        doc["tags"] = TAGS[server]


def main():
    server, path = sys.argv[1], sys.argv[2]
    with open(path) as f:
        doc = json.load(f)

    shorten_schema_names(doc)
    inline_framework_types(doc)
    gc_schemas(doc)

    title, desc = INFO[server]
    doc["info"] = {"title": title, "version": doc.get("info", {}).get("version", "v1"),
                   "description": desc}
    # 추출 환경의 localhost 주소는 의미가 없다. 지운다.
    doc.pop("servers", None)

    enrich(doc, server)
    # apply_fixes 가 'query' 뭉치를 걷어내면 그것만 가리키던 스키마(String{all,empty})가 고아로 남는다
    gc_schemas(doc)
    report_unmatched(doc, server)

    with open(path, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")

    internal = sum(1 for p in doc.get("paths", {}) if p.startswith("/internal"))
    print(f"{server}: 경로 {len(doc.get('paths', {}))}개(내부 {internal}개 포함), "
          f"스키마 {len(doc.get('components', {}).get('schemas', {}))}개")


if __name__ == "__main__":
    main()
