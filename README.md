# pokeclip-api-docs

[pokeclip-mono](https://github.com/3K-PokeClip/PokeClip-mono)의 API 명세를
자동으로 뽑아 GitHub Pages로 배포한다.

**사이트**: https://kth4778.github.io/pokeclip-api-docs/

## 어떻게 도나

```
매일 06:00 KST (또는 수동 실행)
   ↓
mono를 checkout → 서버 4개 bootJar 빌드 (springdoc은 init.gradle로 주입)
   ↓
서버를 하나씩 띄워 /v3/api-docs 추출
   ↓
후처리: 설명 주입 (내부 API·알려진 보안 구멍 포함 — 서비스 안 할 프로젝트라 가리지 않는다)
   ↓
Swagger UI + JSON을 Pages로 배포
```

**mono 저장소는 읽기만 한다.** 의존성 추가도 코드 수정도 없다.

## 파일

| 파일 | 역할 |
|---|---|
| `.github/workflows/docs.yml` | 전체 파이프라인 |
| `init.gradle` | mono를 안 고치고 springdoc을 빌드 순간에만 얹는다 |
| `scripts/extract.sh` | 서버 4개를 차례로 띄워 문서를 뽑는다 |
| `scripts/mint_jwt.py` | auth의 `/v3/api-docs`가 인증에 걸려 있어, CI가 정한 시크릿으로 토큰을 직접 서명한다 |
| `scripts/postprocess.py` | 설명 주입(내부 API·알려진 구멍 포함) |
| `site/index.html` | 쉘 — 상단 탭(API 명세 / DB ERD)으로 두 페이지를 오간다. 해시 `#api`·`#erd`, 단축키 1·2 |
| `site/api.html` | Swagger UI. 드롭다운으로 서버 4개를 고른다 |
| `site/erd.html` | erdcloud풍 인터랙티브 ERD — 팬·줌·테이블 드래그. 데이터는 `gen_erd.py`가 실제 스키마에서 뽑은 `schema.json` |
| `scripts/gen_erd.py` | Flyway 적용이 끝난 postgres에서 테이블·키·코멘트를 읽는다 |

## 알아둘 것

- **내부 API(`/internal/**`)와 알려진 보안 구멍도 전부 실었다** (2026-08-18 결정).
  이 프로젝트는 서비스하지 않으므로 공격면을 가릴 이유가 없다 — 팀 안에서
  계약과 함정을 한눈에 보는 것이 더 값지다는 판단. 실제로 배포하는 프로젝트라면
  이 결정을 그대로 베끼지 마라.
- **설명 문구는 `postprocess.py`에 하드코딩돼 있다.** mono 코드에 `@Operation`
  어노테이션이 들어가면 그쪽이 정본이 되고 이 스크립트의 ENRICH는 비운다.
  코드에 없는 경로는 조용히 건너뛰므로 mono가 바뀌어도 깨지지 않는다.
- **서버 하나라도 추출에 실패하면 배포 전체가 실패한다.** 조용히 빼고
  배포하면 "문서가 없다 = API가 없다"로 읽히기 때문이다.
- **mono가 필수 환경변수를 늘리면 `docs.yml`의 `env:`도 같이 고쳐야 한다.**
  2026-08-17에 치지직 연동(POK-93)이 auth 필수값을 여섯→아홉으로 늘렸는데
  `docs.yml`을 안 고쳐 배포가 한 번 실패했다(`CHZZK_CLIENT_ID` 등 3개 누락 —
  auth가 의도적으로 부팅을 거부하는 값들이라 조용히 안 넘어가고 바로 터진다).
  각 서버의 필수 환경변수 정본은 `services/<서버>/CLAUDE.md`(로컬 전용이라
  여기서 못 본다) 또는 mono의 커밋되는 `services/README.md`다.
- 갱신은 매일 1회다. 지금 바로 갱신하려면 Actions 탭 → API docs → Run workflow.
