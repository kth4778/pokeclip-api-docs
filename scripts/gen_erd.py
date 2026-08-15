"""마이그레이션이 적용된 postgres에서 스키마를 읽어 schema.json을 만든다.

SQL 파일을 파싱하지 않고 실제 DB를 읽는 이유: Flyway가 적용한 결과가 정본이고,
파서는 SQL 문법의 부분집합만 이해해 조용히 틀린다. extract.sh가 auth를 한 번
띄운 뒤에 부르므로 이 시점의 DB에는 V1xx가 전부 적용돼 있다.

flyway_% 이력 테이블은 도메인이 아니라서 뺀다.
"""
import csv
import io
import json
import os
import shlex
import subprocess
import sys


def psql(query: str):
    """psql --csv로 질의해 dict 목록으로 돌려준다.

    PSQL_BIN으로 명령을 바꿀 수 있다 — psql이 없는 로컬에서
    "docker exec -i <컨테이너> psql" 같은 대체 경로를 쓰기 위해서다.
    CI(ubuntu)는 기본값 psql을 그대로 쓴다.
    """
    conn = (
        f"host={os.environ.get('DB_HOST', 'localhost')} "
        f"port={os.environ.get('DB_PORT', '5432')} "
        f"dbname={os.environ.get('POSTGRES_DB', 'pokeclip')} "
        f"user={os.environ.get('POSTGRES_USER', 'pokeclip')} "
        f"password={os.environ.get('POSTGRES_PASSWORD', '')}"
    )
    cmd = shlex.split(os.environ.get("PSQL_BIN", "psql"))
    out = subprocess.run(
        cmd + [conn, "--csv", "-v", "ON_ERROR_STOP=1", "-c", query],
        check=True, capture_output=True, text=True,
    ).stdout
    return list(csv.DictReader(io.StringIO(out)))


TABLES = """
SELECT c.relname AS table_name,
       COALESCE(obj_description(c.oid), '') AS comment
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
  AND c.relname NOT LIKE 'flyway%'
ORDER BY c.relname
"""

COLUMNS = """
SELECT c.table_name, c.column_name, c.udt_name,
       c.character_maximum_length AS max_len,
       c.is_nullable, COALESCE(c.column_default, '') AS column_default,
       COALESCE(col_description(pc.oid, c.ordinal_position), '') AS comment
FROM information_schema.columns c
JOIN pg_class pc ON pc.relname = c.table_name
JOIN pg_namespace pn ON pn.oid = pc.relnamespace AND pn.nspname = 'public'
WHERE c.table_schema = 'public' AND c.table_name NOT LIKE 'flyway%'
ORDER BY c.table_name, c.ordinal_position
"""

KEYS = """
SELECT tc.table_name, kcu.column_name, tc.constraint_type, tc.constraint_name,
       (SELECT count(*) FROM information_schema.key_column_usage k2
         WHERE k2.constraint_name = tc.constraint_name
           AND k2.table_schema = tc.table_schema) AS ncols
FROM information_schema.table_constraints tc
JOIN information_schema.key_column_usage kcu
  ON kcu.constraint_name = tc.constraint_name
 AND kcu.table_schema = tc.table_schema
WHERE tc.table_schema = 'public'
  AND tc.constraint_type IN ('PRIMARY KEY', 'UNIQUE')
"""

FOREIGN_KEYS = """
SELECT tc.table_name, kcu.column_name,
       ccu.table_name AS ref_table, ccu.column_name AS ref_column
FROM information_schema.table_constraints tc
JOIN information_schema.key_column_usage kcu
  ON kcu.constraint_name = tc.constraint_name
 AND kcu.table_schema = tc.table_schema
JOIN information_schema.constraint_column_usage ccu
  ON ccu.constraint_name = tc.constraint_name
 AND ccu.table_schema = tc.table_schema
WHERE tc.table_schema = 'public' AND tc.constraint_type = 'FOREIGN KEY'
"""

# 부분 유니크 인덱스(예: stream_keys의 "살아 있는 키는 계정당 하나")는
# 제약이 아니라 인덱스라 위 질의에 안 잡힌다. 표시는 하되 UK와 구분한다.
PARTIAL_UNIQUE = """
SELECT t.relname AS table_name, a.attname AS column_name
FROM pg_index i
JOIN pg_class t ON t.oid = i.indrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(i.indkey)
WHERE n.nspname = 'public' AND i.indisunique AND i.indpred IS NOT NULL
  AND t.relname NOT LIKE 'flyway%'
"""


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else "site/specs/schema.json"

    tables = {r["table_name"]: {"name": r["table_name"], "comment": r["comment"],
                                "columns": []} for r in psql(TABLES)}

    keys = {}  # (table, column) -> set of marks
    for r in psql(KEYS):
        mark = "PK" if r["constraint_type"] == "PRIMARY KEY" else "UK"
        # 복합 키는 "UK(2)"처럼 표시한다 — 컬럼 하나하나가 유일한 게 아니라
        # 묶음이 유일하다는 뜻이다. chat_messages의 4컬럼 지문이 그렇다.
        if int(r["ncols"]) > 1:
            mark = f"{mark}({r['ncols']})"
        keys.setdefault((r["table_name"], r["column_name"]), set()).add(mark)
    for r in psql(PARTIAL_UNIQUE):
        keys.setdefault((r["table_name"], r["column_name"]), set()).add("UK*")

    fks = {}  # (table, column) -> {table, column}
    relations = []
    for r in psql(FOREIGN_KEYS):
        keys.setdefault((r["table_name"], r["column_name"]), set()).add("FK")
        fks[(r["table_name"], r["column_name"])] = {
            "table": r["ref_table"], "column": r["ref_column"]}

    for r in psql(COLUMNS):
        t, col = r["table_name"], r["column_name"]
        typ = r["udt_name"]
        if r["max_len"]:
            typ += f"({r['max_len']})"
        tables[t]["columns"].append({
            "name": col,
            "type": typ,
            "nullable": r["is_nullable"] == "YES",
            "default": r["column_default"],
            "comment": r["comment"],
            "keys": sorted(keys.get((t, col), [])),
            "ref": fks.get((t, col)),
        })
        ref = fks.get((t, col))
        if ref:
            relations.append({
                "from": t, "column": col,
                "to": ref["table"], "to_column": ref["column"],
                "nullable": r["is_nullable"] == "YES",
            })

    result = {"tables": sorted(tables.values(), key=lambda x: x["name"]),
              "relations": relations}
    with open(out_path, "w") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"schema.json: 테이블 {len(tables)}개, 관계 {len(relations)}개")


if __name__ == "__main__":
    main()
