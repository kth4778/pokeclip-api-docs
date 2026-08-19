// docs-ensure-schema는 문서 파이프라인(kth4778/pokeclip-api-docs) 전용이다.
// mono에는 커밋되지 않는다 — extract.sh가 CI 체크아웃의 media/cmd/ 밑에
// 이 파일을 복사해 넣고 go run으로 실행한 뒤 버린다. init.gradle이 auth에
// springdoc을 주입하는 것과 같은 방식 — mono는 읽기만 한다.
//
// media는 REST API가 없다(Go CLI 훅 기록기 + 사이드카일 뿐 HTTP 서버가 없다).
// 대신 stream_segments 표 하나를 가진다 — 정본 DDL은 media/internal/index/ddl.go,
// 소유자는 1번(Media)이다(ADR-0001). 이 프로그램은 그 DDL을 실행하는 실제 함수
// (EnsureSchema)를 그대로 불러 쓴다 — SQL을 따로 베끼면 ddl.go가 바뀔 때 조용히
// 어긋난다.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/3K-PokeClip/pokeclip-mono/media/internal/config"
	"github.com/3K-PokeClip/pokeclip-mono/media/internal/index"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pool, err := pgxpool.New(context.Background(), cfg.PGDSN)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer pool.Close()
	if err := index.EnsureSchema(context.Background(), pool); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("media: stream_segments schema ensured")
}
