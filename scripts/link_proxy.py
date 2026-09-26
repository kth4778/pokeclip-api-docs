"""clip 의 중계 문 셋에 수집 서버의 응답 모양을 붙인다.

clip 은 수집 서버의 답을 **문자열 그대로** 넘기므로(BroadcastChatController) springdoc 에는 응답이
`string` 으로만 보인다. 그렇다고 clip 쪽에 모양을 손으로 다시 적으면 수집 서버가 칸을 늘릴 때 한쪽만
낡는다. 그래서 **정본(수집 서버 스펙)에서 복사**한다 — 서버마다 따로 후처리한 뒤, 둘 다 있을 때 한 번.
"""
import json, sys

OUT = sys.argv[1]
# clip 문 → 수집 서버 문(같은 이름)
PROXIES = {
    "/api/clip/broadcasts/{streamId}/chat-messages": "/internal/streams/{streamId}/chat-messages",
    "/api/clip/broadcasts/{streamId}/chat-chart": "/internal/streams/{streamId}/chat-chart",
    "/api/clip/broadcasts/{streamId}/broadcast-info": "/internal/streams/{streamId}/broadcast-info",
}


def refs(node, found):
    if isinstance(node, dict):
        r = node.get("$ref")
        if isinstance(r, str) and r.startswith("#/components/schemas/"):
            found.add(r.rsplit("/", 1)[-1])
        for v in node.values():
            refs(v, found)
    elif isinstance(node, list):
        for v in node:
            refs(v, found)


clip = json.load(open(f"{OUT}/clip.json"))
col = json.load(open(f"{OUT}/chat-collector.json"))
col_schemas = col.get("components", {}).get("schemas", {})
clip_schemas = clip.setdefault("components", {}).setdefault("schemas", {})

linked = 0
for clip_path, col_path in PROXIES.items():
    op = clip.get("paths", {}).get(clip_path, {}).get("get")
    src = col.get("paths", {}).get(col_path, {}).get("get", {}).get("responses", {}).get("200", {})
    # 수집 서버 스펙은 응답 형식이 `*/*` 로 찍힌다(springdoc 기본값). 이름을 가리지 않고 첫 것을 쓴다 —
    # 처음엔 application/json 만 찾아서 셋 다 「한쪽 문이 없다」로 빠졌다(2026-09-26 로컬 실측).
    content = next(iter(src.get("content", {}).values()), None)
    if op is None or content is None:
        print(f"  ⚠ 중계 연결 실패: {clip_path} — 한쪽 문이 없다")
        continue
    op.setdefault("responses", {}).setdefault("200", {})["content"] = {"application/json": content}
    # 따라오는 스키마를 전부(중첩까지) 복사한다
    todo = set(); refs(content, todo); done = set()
    while todo:
        name = todo.pop()
        if name in done or name not in col_schemas:
            continue
        done.add(name)
        if name in clip_schemas and clip_schemas[name] != col_schemas[name]:
            # clip 에 같은 이름의 다른 스키마가 있으면 덮지 않는다 — 조용히 덮으면 08-25 의 사고가 된다
            raise SystemExit(f"중계 스키마 이름 충돌: clip 에 이미 다른 {name} 이 있다")
        clip_schemas[name] = col_schemas[name]
        refs(col_schemas[name], todo)
    linked += 1

with open(f"{OUT}/clip.json", "w") as f:
    json.dump(clip, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(f"중계 문 {linked}/{len(PROXIES)}개에 수집 서버 응답 모양을 붙였다")
