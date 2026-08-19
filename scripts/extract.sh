#!/usr/bin/env bash
# 서버 4개를 차례로 띄워 /v3/api-docs를 뽑는다.
#
# 전제:
#   - mono/services 아래에 bootJar가 이미 빌드돼 있다
#   - postgres가 localhost:5432에 떠 있다 (auth·clip이 쓴다)
#   - auth용 환경변수 6개가 export돼 있다 (JWT_SECRET 등)
#
# 서버 하나라도 실패하면 즉시 죽는다. 조용히 빼고 배포하면
# "문서가 없다 = API가 없다"로 읽히기 때문이다.
set -euo pipefail

MONO="${MONO_DIR:-mono}"
OUT="${OUT_DIR:-site/specs}"
mkdir -p "$OUT"

# 이름 | 포트 | 인증 토큰 필요 여부
SERVERS=(
  "auth|8082|jwt"
  "clip|8081|none"
  "chat-collector|8083|none"
  "chat-detector|8084|none"
)

extract_one() {
  local name="$1" port="$2" auth="$3"
  local jar log="/tmp/${name}.log" pid
  # -plain.jar(부트 매니페스트가 없는 일반 jar)는 실행이 안 된다. 거른다.
  jar=$(ls "$MONO/services/$name/build/libs/"*.jar | grep -v -- '-plain' | head -1)

  echo "── $name: $jar"
  # clip만 baseline을 허용한다. auth가 먼저 스키마를 채우는데 clip은 자기
  # 이력표(flyway_schema_history_clip)가 없어 "non-empty schema"로 부팅을
  # 거부하기 때문이다. 추출용 DB는 일회용이라 baseline의 부작용이 없다.
  if [ "$name" = "clip" ]; then
    SPRING_FLYWAY_BASELINE_ON_MIGRATE=true java -jar "$jar" >"$log" 2>&1 &
  else
    java -jar "$jar" >"$log" 2>&1 &
  fi
  pid=$!

  local header=()
  if [ "$auth" = "jwt" ]; then
    header=(-H "Authorization: Bearer $(python3 scripts/mint_jwt.py)")
  fi

  # 90초 안에 200이 안 오면 실패. 프로세스가 먼저 죽어도 실패.
  local ok=""
  for _ in $(seq 90); do
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "✗ $name 프로세스가 죽었다. 로그 마지막 40줄:"
      tail -40 "$log"
      return 1
    fi
    # ${header[@]+...} — 빈 배열을 set -u에서도 안전하게 푼다 (bash 3.2 호환)
    if curl -sf ${header[@]+"${header[@]}"} "http://localhost:$port/v3/api-docs" -o "$OUT/$name.json"; then
      ok=1
      break
    fi
    sleep 1
  done

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true

  if [ -z "$ok" ]; then
    echo "✗ $name: 90초 안에 /v3/api-docs가 200을 주지 않았다. 로그 마지막 40줄:"
    tail -40 "$log"
    return 1
  fi

  python3 scripts/postprocess.py "$name" "$OUT/$name.json"
}

for entry in "${SERVERS[@]}"; do
  IFS='|' read -r name port auth <<<"$entry"
  extract_one "$name" "$port" "$auth"
done

# ── media: REST API는 없다(Go 훅 기록기 + 사이드카). stream_segments 표만
# 있어서 ERD용으로 그 스키마만 만든다 — media/internal/index/ddl.go의
# 실제 EnsureSchema를 그대로 불러 쓴다(scripts/media-ensure-schema.go 참고).
echo "── media: stream_segments 스키마 보장"
mkdir -p "$MONO/media/cmd/docs-ensure-schema"
cp scripts/media-ensure-schema.go "$MONO/media/cmd/docs-ensure-schema/main.go"
(cd "$MONO/media" && POSTGRES_HOST="${POSTGRES_HOST:-localhost}" go run ./cmd/docs-ensure-schema)

# ERD 데이터. auth·media가 위에서 스키마를 만들었으므로 이 시점의 postgres에는
# 전부 적용돼 있다 — 그 실제 스키마를 읽는다.
python3 scripts/gen_erd.py "$OUT/schema.json"

# Swagger UI 드롭다운이 읽는 목록. 성공한 것만 여기 실리므로,
# 위에서 하나라도 실패하면 여기까지 오지 않는다.
python3 - "$OUT" <<'EOF'
import json, sys, os
out = sys.argv[1]
LABEL = {
    "auth": "auth — 로그인·토큰·스트림키 (8082)",
    "clip": "clip — 방송 세션·클립·승인 (8081)",
    "chat-collector": "chat-collector — 치지직 채팅 수집 (8083)",
    "chat-detector": "chat-detector — 하이라이트 판별 (8084)",
}
urls = [{"url": f"specs/{n}.json", "name": LABEL[n]}
        for n in ["auth", "clip", "chat-collector", "chat-detector"]
        if os.path.exists(f"{out}/{n}.json")]
with open(f"{out}/manifest.json", "w") as f:
    json.dump(urls, f, ensure_ascii=False, indent=2)
print(f"manifest: {len(urls)}개 서버")
EOF

echo "완료. $OUT:"
ls -la "$OUT"
