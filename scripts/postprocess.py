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

TAGS = {}
TAGS["auth"] = [
    {"name": "인증", "description": "구글 로그인과 토큰 수명 관리."},
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
OPS["clip"] = {
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
        {"401": {"description": "access 토큰이 없거나 유효하지 않다."},
         "403": {"description": "이 방송을 볼 권한이 없다(auth의 위임 판정 결과)."},
         "404": {"description": "그런 방송이 없거나, 볼 수 있는 기한(VOD 보관 기간)이 지났다."}},
    ),
    ("/api/clip/broadcasts/{streamId}/events", "get"): (
        "점프카드 실시간 수신 (SSE)",
        "🔴 **일반 JSON API가 아니다. SSE(Server-Sent Events)** — 연결을 열어 두면 서버가 "
        "카드를 밀어 준다. `Content-Type: text/event-stream`.\n\n"
        "연결하는 순간 **현재 카드 전부를 스냅샷으로 먼저** 받고, 그 뒤로 새 카드·변경이 이어서 온다.\n\n"
        "방송이 끝나면 `ended` 이벤트가 오고 서버가 연결을 닫는다. "
        "연결 수명은 최대 **4시간**이고, access 토큰이 먼저 만료되면 그 시점에 닫힌다.\n\n"
        "`Last-Event-ID` 헤더(또는 `lastEventId` 파라미터)를 받긴 하지만 **지금은 쓰지 않는다** — "
        "재연결 때도 전체 스냅샷을 다시 보낸다.",
        [{"bearerAuth": []}], "편집기",
        {"401": {"description": "access 토큰이 없거나 유효하지 않다."},
         "404": {"description": "그런 방송이 없다."}},
    ),
    ("/api/clip/jump-cards/{id}/claim", "post"): (
        "점프카드 집기",
        "**「내가 이 카드를 편집한다」고 찍는다.** 편집자 여러 명이 같은 카드를 동시에 "
        "건드리는 것을 막는 자리다.\n\n"
        "집은 상태에는 **시한(TTL)이 있다** — `claimExpiresAt`이 지나면 자동으로 풀린 것으로 본다. "
        "치우는 배경 작업이 없어서 집을 때 판정하므로, 그 값은 표에 저장된 값이 아니라 계산값이다.",
        [{"bearerAuth": []}], "편집기",
        {"401": {"description": "access 토큰이 없거나 유효하지 않다."},
         "403": {"description": "이 방송을 볼 권한이 없다."},
         "404": {"description": "그런 카드가 없다."},
         "409": {"description": "다른 사람이 이미 집었고 아직 시한이 안 지났다."}},
    ),
    ("/api/clip/jump-cards/{id}/claim", "delete"): (
        "점프카드 놓기",
        "집은 것을 스스로 푼다. 시한이 지나기를 기다리지 않고 바로 남에게 넘길 때 쓴다.",
        [{"bearerAuth": []}], "편집기",
        {"401": {"description": "access 토큰이 없거나 유효하지 않다."},
         "403": {"description": "이 방송을 볼 권한이 없다."},
         "404": {"description": "그런 카드가 없다."}},
    ),
    ("/api/clip/jump-cards/{id}/hide", "post"): (
        "점프카드 숨기기",
        "쓸모없는 카드를 목록에서 치운다. **행을 지우지 않고 `hidden` 표시만 한다** — "
        "판별기가 왜 이걸 골랐는지 나중에 되짚을 수 있어야 해서다.",
        [{"bearerAuth": []}], "편집기",
        {"401": {"description": "access 토큰이 없거나 유효하지 않다."},
         "403": {"description": "이 방송을 볼 권한이 없다."},
         "404": {"description": "그런 카드가 없다."}},
    ),
    ("/api/clip/jump-cards/{id}/hide", "delete"): (
        "점프카드 되돌리기",
        "숨긴 것을 다시 꺼낸다.\n\n"
        "**숨긴 사람이 아니어도 누구나 되돌릴 수 있다** — 숨긴 사람만 가능하게 하면 "
        "그 사람이 자리를 비웠을 때 아무도 못 되돌린다.",
        [{"bearerAuth": []}], "편집기",
        {"401": {"description": "access 토큰이 없거나 유효하지 않다."},
         "403": {"description": "이 방송을 볼 권한이 없다."},
         "404": {"description": "그런 카드가 없다."}},
    ),
    ("/internal/broadcasts/{streamId}/highlights", "post"): (
        "점프카드 넣기 (내부 전용)",
        "**판별기가 「여기가 하이라이트다」를 넣는 문**이다(계약 2A).\n\n"
        "**201과 200을 가른다** — 새로 만들었으면 201, 같은 `eventId`가 이미 있으면 200이다. "
        "판별기가 재전송했을 때 로그에서 중복과 진짜 신규를 구분할 수 있게 한 것이라 "
        "**둘 다 성공**이다(재시도는 안전하다).",
        [{"internalToken": []}], "내부 (서버 간 연동)",
        {"400": {"description": "요청이 잘못됐다 — 창이 뒤집혔거나(`startMs >= endMs`), 지점이 창 밖이거나, "
                                "`eventId`가 128자를 넘거나, 모르는 `source`다. "
                                "**재시도해도 같은 결과라 판별기는 멈춰야 한다.**"},
         "401": {"description": "X-Internal-Token 헤더가 없거나 값이 틀리다."},
         "404": {"description": "그런 방송이 없다."}},
    ),
}
OK_DESC["clip"] = {
    ("/api/clip/broadcasts/{streamId}/segments", "get", "200"): "조회 성공.",
    ("/api/clip/broadcasts/{streamId}/events", "get", "200"):
        "연결됨. **여기서 끝이 아니라 이제부터 이벤트가 흘러온다**(text/event-stream).",
    ("/api/clip/jump-cards/{id}/claim", "post", "200"): "집기 성공. 갱신된 카드를 돌려준다.",
    ("/api/clip/jump-cards/{id}/claim", "delete", "204"): "놓기 완료. 본문이 없다.",
    ("/api/clip/jump-cards/{id}/hide", "post", "200"): "숨김 완료. 갱신된 카드를 돌려준다.",
    ("/api/clip/jump-cards/{id}/hide", "delete", "200"): "되돌림 완료. 갱신된 카드를 돌려준다.",
    ("/internal/broadcasts/{streamId}/highlights", "post", "200"):
        "**이미 있던 카드다**(같은 eventId 재전송). 성공으로 다뤄도 된다.",
    ("/internal/broadcasts/{streamId}/highlights", "post", "201"): "새 카드를 만들었다.",
}
FIELDS["clip"] = {
    "SegmentWindowResponse": {
        "_": "요청한 구간에 걸친 조각 목록. **S3 키는 실리지 않는다.**",
        "complete": "요청 구간이 조각으로 전부 덮였으면 true. false면 아직 안 올라온 부분이 있다.",
        "availableFromMs": "실제로 덮인 시작 지점. **조각 경계라 요청보다 이를 수 있다.**",
        "availableUntilMs": "실제로 덮인 끝 지점. **조각 경계라 요청보다 늦을 수 있다.**",
        "segments": "조각 목록.",
    },
    "Item": {
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
    # 같은 이름의 중첩 record가 둘이라 FQN 축약이 서로 다른 이름을 준다.
    # HighlightRequest.Window → JumpcardWindow · JumpCardSnapshot.Window → Window
    "JumpcardWindow": {
        "_": "잘라낼 구간(요청).",
        "startMs": "구간 시작(방송 시작 기준 ms).",
        "endMs": "구간 끝. **startMs보다 커야 한다.**",
    },
    "Window": {
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
}
TAGS["clip"] = [
    {"name": "편집기", "description": "편집자가 쓰는 문. 사용자 JWT가 필요하고, "
                                  "그 방송을 볼 권한이 있는지 auth에 물어 확인한다."},
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
        "observedAt": "이 답을 만든 시각.",
    },
}
TAGS["chat-collector"] = [
    {"name": "내부 (서버 간 연동)", "description": "clip만 부른다. 사용자 JWT로는 통과할 수 없다."},
]


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
            # com.pokeclip.auth.chzzk.api.dto.LinkRequest → 'chzzk'
            hint = parts[parts.index("api") - 1] if "api" in parts else ""
            rename[fq] = (hint[:1].upper() + hint[1:] + simple) if hint else simple

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


def enrich(doc, server):
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

    with open(path, "w") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")

    internal = sum(1 for p in doc.get("paths", {}) if p.startswith("/internal"))
    print(f"{server}: 경로 {len(doc.get('paths', {}))}개(내부 {internal}개 포함), "
          f"스키마 {len(doc.get('components', {}).get('schemas', {}))}개")


if __name__ == "__main__":
    main()
