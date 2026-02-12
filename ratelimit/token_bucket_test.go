package ratelimit

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}

	if _, err := db.ExecContext(context.Background(), `
CREATE TABLE token_buckets (
  storage_key TEXT NOT NULL,
  bucket_key TEXT NOT NULL,
  count INTEGER NOT NULL,
  refilled_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY(storage_key, bucket_key)
);
`); err != nil {
		t.Fatalf("create token_buckets table: %v", err)
	}

	if _, err := db.ExecContext(context.Background(), `
CREATE INDEX token_buckets_updated_at_ms_idx
ON token_buckets(updated_at_ms);
`); err != nil {
		t.Fatalf("create token_buckets index: %v", err)
	}

	t.Cleanup(func() {
		_ = db.Close()
	})

	return db
}

func TestSQLiteTokenBucketConsumeAndRefill(t *testing.T) {
	db := setupTestDB(t)

	limiter, err := NewTokenBucket(context.Background(), db, "test", 2, 2*time.Second)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	limiter.now = func() time.Time { return now }

	allowed, err := limiter.Consume(context.Background(), "ip:1", 1)
	if err != nil || !allowed {
		t.Fatalf("expected first consume allowed, allowed=%v err=%v", allowed, err)
	}

	allowed, err = limiter.Consume(context.Background(), "ip:1", 1)
	if err != nil || !allowed {
		t.Fatalf("expected second consume allowed, allowed=%v err=%v", allowed, err)
	}

	allowed, err = limiter.Consume(context.Background(), "ip:1", 1)
	if err != nil {
		t.Fatalf("consume error: %v", err)
	}
	if allowed {
		t.Fatal("expected third consume denied")
	}

	now = now.Add(2 * time.Second)
	allowed, err = limiter.Consume(context.Background(), "ip:1", 1)
	if err != nil || !allowed {
		t.Fatalf("expected refill consume allowed, allowed=%v err=%v", allowed, err)
	}
}

func TestSQLiteTokenBucketPruneIdle(t *testing.T) {
	db := setupTestDB(t)

	limiter, err := NewTokenBucket(context.Background(), db, "test-prune", 2, time.Second)
	if err != nil {
		t.Fatalf("new limiter: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	limiter.now = func() time.Time { return now }

	allowed, err := limiter.Consume(context.Background(), "ip:1", 1)
	if err != nil || !allowed {
		t.Fatalf("expected consume allowed, allowed=%v err=%v", allowed, err)
	}

	now = now.Add(2 * time.Hour)
	if err := limiter.PruneIdle(context.Background(), 1*time.Hour); err != nil {
		t.Fatalf("prune idle: %v", err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM token_buckets WHERE storage_key = ?", "test-prune").Scan(&count)
	if err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected all rows pruned, got %d", count)
	}
}
