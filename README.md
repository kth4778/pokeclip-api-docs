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
후처리: /internal/** 제거 · 안 쓰는 스키마 제거 · 설명 주입
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
| `scripts/postprocess.py` | 내부 API 제거 + 설명 주입 |
| `site/index.html` | Swagger UI. 드롭다운으로 서버 4개를 고른다 |

## 알아둘 것

- **내부 API(`/internal/**`)는 공개 문서에서 뺀다.** 이 사이트는 public이다.
  내부 계약은 mono의 `services/README.md`에 있다.
- **설명 문구는 `postprocess.py`에 하드코딩돼 있다.** mono 코드에 `@Operation`
  어노테이션이 들어가면 그쪽이 정본이 되고 이 스크립트의 ENRICH는 비운다.
  코드에 없는 경로는 조용히 건너뛰므로 mono가 바뀌어도 깨지지 않는다.
- **서버 하나라도 추출에 실패하면 배포 전체가 실패한다.** 조용히 빼고
  배포하면 "문서가 없다 = API가 없다"로 읽히기 때문이다.
- 갱신은 매일 1회다. 지금 바로 갱신하려면 Actions 탭 → API docs → Run workflow.
