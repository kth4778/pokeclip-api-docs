# pokeclip-api-docs

[pokeclip-mono](https://github.com/3K-PokeClip/PokeClip-mono)의 API 명세·DB
스키마를 자동으로 뽑아 GitHub Pages로 배포한다.

**사이트**: https://kth4778.github.io/pokeclip-api-docs/

## 어떻게 도나

```
10분마다 mono/develop의 최신 커밋을 확인 (또는 push·수동 실행)
   ↓ (바뀐 게 있을 때만 아래로 진행 — check 잡)
mono를 develop으로 checkout → Java 서버 4개 bootJar 빌드 (springdoc은 init.gradle로 주입)
   ↓
서버를 하나씩 띄워 /v3/api-docs 추출
   ↓
media(Go): REST API는 없다. stream_segments 표만 실제 EnsureSchema로 만든다
   ↓
후처리: 설명 주입 (내부 API·알려진 보안 구멍 포함 — 서비스 안 할 프로젝트라 가리지 않는다)
   ↓
Swagger UI + 인터랙티브 ERD를 Pages로 배포 (배포물에 mono 커밋 SHA를 같이 남긴다)
```

**mono 저장소는 읽기만 한다.** 의존성 추가도 코드 수정도 없다 — Java는
`init.gradle`을, Go는 `media-ensure-schema.go`를 CI 체크아웃에만 얹었다 지운다.

## 다루는 대상과 안 다루는 대상

| 영역 | API | DB | 비고 |
|---|---|---|---|
| `services/auth` | O (21개, 내부 포함) | O | |
| `services/clip` | 없음 | O (`broadcasts`·`broadcast_events`) | REST 컨트롤러가 아직 0개 — SQS 소비만 한다 |
| `services/chat-collector` | 없음 | O (`chat_messages`) | 수집은 나가는 연결이라 REST API가 없다 |
| `services/chat-detector` | 없음 | 없음 | 코드가 아직 없다 |
| `media` | **없음(구조적으로)** | O (`stream_segments`) | Go CLI 훅 기록기 + 사이드카다. `ListenAndServe`가 코드 어디에도 없다 — HTTP 서버 자체가 아니라서 API 문서 대상이 아니다 |
| `workers/ai`·`render`·`upload` | 미확인 | 미확인 | **2026-08-19 기준 코드가 없다**(`.gitkeep`뿐). 생기면 이 표를 다시 본다 — 파일 소비자라 REST API도 DB도 없을 가능성이 높다(README: "요청을 받아 바로 답하는 서버가 아니다") |
| `obs-plugin` | 없음(구조적으로) | 없음 | **2026-08-19 기준 코드가 없다.** 스트리머 PC에 까는 C++ 데스크톱 플러그인이라, 코드가 생겨도 REST API를 낼 종류가 아니다(SRT로 내보내기만 한다) |

## 파일

| 파일 | 역할 |
|---|---|
| `.github/workflows/docs.yml` | 전체 파이프라인. `check`(폴링) → `build` → `deploy` 3잡 |
| `init.gradle` | mono를 안 고치고 springdoc을 빌드 순간에만 얹는다(Java 4서버) |
| `scripts/media-ensure-schema.go` | mono를 안 고치고 media의 실제 `config.Load`·`index.EnsureSchema`를 그대로 불러 `stream_segments` 표만 만든다(Go) |
| `scripts/extract.sh` | Java 서버를 차례로 띄워 문서를 뽑고, media 스키마도 보장한다 |
| `scripts/mint_jwt.py` | auth의 `/v3/api-docs`가 인증에 걸려 있어, CI가 정한 시크릿으로 토큰을 직접 서명한다 |
| `scripts/postprocess.py` | 설명 주입(내부 API·알려진 구멍 포함) |
| `scripts/gen_erd.py` | Flyway·EnsureSchema 적용이 끝난 postgres에서 테이블·키·코멘트를 읽는다 — 서버 구분 없이 공유 DB 전체를 본다 |
| `site/index.html` | 쉘 — 상단 탭(API 명세 / DB ERD)으로 두 페이지를 오간다. 해시 `#api`·`#erd`, 단축키 1·2 |
| `site/api.html` | Swagger UI. 드롭다운으로 서버를 고른다 |
| `site/erd.html` | erdcloud풍 인터랙티브 ERD — 팬·줌·테이블 드래그. 데이터는 `gen_erd.py`가 뽑은 `schema.json` |

## 알아둘 것

- **자동 갱신은 "머지될 때마다"가 아니라 "10분 안에"다.** 진짜 즉시 트리거를 걸려면
  mono가 이 레포를 호출하는 워크플로를 가져야 하는데, mono는 팀 공용 저장소라
  `.github/`를 나 혼자 고치지 않는다(팀 조율 필요). 대신 이 레포 자체(`check` 잡)가
  mono/develop의 `git ls-remote`만 10분마다 확인해, **바뀐 게 없으면 빌드를 통째로
  건너뛴다** — 배포 이력을 지저분하게 만들지 않으면서 사실상 실시간에 가깝게 간다.
  마지막으로 배포한 mono 커밋 SHA는 `site/specs/mono-sha.txt`에 같이 실려서
  다음 폴링의 비교 기준이 된다.
- **내부 API(`/internal/**`)와 알려진 보안 구멍도 전부 실었다** (2026-08-18 결정).
  이 프로젝트는 서비스하지 않으므로 공격면을 가릴 이유가 없다 — 팀 안에서
  계약과 함정을 한눈에 보는 것이 더 값지다는 판단. 실제로 배포하는 프로젝트라면
  이 결정을 그대로 베끼지 마라.
- **설명 문구는 `postprocess.py`·`erd.html`에 하드코딩돼 있다.** mono 코드에
  `@Operation` 어노테이션이나 DB 컬럼 코멘트가 들어가면 그쪽이 우선이고, 이 하드코딩은
  보완일 뿐이다. 코드에 없는 대상은 조용히 건너뛰므로 mono가 바뀌어도 깨지지 않는다 —
  다만 **새로 생긴 API·표는 자동으로 한글 설명이 안 붙는다.** 구조(경로·컬럼·타입)는
  자동으로 뜨지만 "왜 이렇게 만들었는지"는 누군가 mono를 읽고 채워야 한다.
- **서버 하나라도 추출에 실패하면 배포 전체가 실패한다.** 조용히 빼고
  배포하면 "문서가 없다 = API가 없다"로 읽히기 때문이다.
- **mono가 필수 환경변수를 늘리면 `docs.yml`의 `env:`도 같이 고쳐야 한다.**
  2026-08-17에 치지직 연동(POK-93)이 auth 필수값을 여섯→아홉으로 늘렸는데
  `docs.yml`을 안 고쳐 배포가 한 번 실패했다(`CHZZK_CLIENT_ID` 등 3개 누락 —
  auth가 의도적으로 부팅을 거부하는 값들이라 조용히 안 넘어가고 바로 터진다).
  각 서버의 필수 환경변수 정본은 `services/<서버>/CLAUDE.md`(로컬 전용이라
  여기서 못 본다) 또는 mono의 커밋되는 `services/README.md`다.
- 지금 바로 갱신하려면 Actions 탭 → API docs → Run workflow(폴링과 무관하게 돈다).
