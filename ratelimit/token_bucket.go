package ratelimit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type TokenBucket struct {
	db               *sql.DB
	storageKey       string
	max              int64
	refillIntervalMs int64
	now              func() time.Time
}

func NewTokenBucket(ctx context.Context, db *sql.DB, storageKey string, max int64, refillInterval time.Duration) (*TokenBucket, error) {
	if db == nil {
		return nil, errors.New("ratelimit db is required")
	}
	if storageKey == "" {
		return nil, errors.New("ratelimit storage key is required")
	}
	if max <= 0 {
		return nil, errors.New("ratelimit max must be positive")
	}

	intervalMs := refillInterval.Milliseconds()
	if intervalMs < 1 {
		intervalMs = 1000
	}

	return &TokenBucket{
		db:               db,
		storageKey:       storageKey,
		max:              max,
		refillIntervalMs: intervalMs,
		now:              time.Now,
	}, nil
}

func (l *TokenBucket) Consume(ctx context.Context, key string, cost int64) (bool, error) {
	if l == nil {
		return false, errors.New("ratelimit limiter is nil")
	}
	if cost <= 0 || cost > l.max {
		return false, nil
	}
	if key == "" {
		key = "anonymous"
	}

	nowMs := l.now().UTC().UnixMilli()

	conn, err := l.db.Conn(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return false, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	var count int64
	var refilledAtMs int64
	err = conn.QueryRowContext(
		ctx,
		"SELECT count, refilled_at_ms FROM token_buckets WHERE storage_key = ? AND bucket_key = ?",
		l.storageKey,
		key,
	).Scan(&count, &refilledAtMs)

	if errors.Is(err, sql.ErrNoRows) {
		_, err = conn.ExecContext(
			ctx,
			"INSERT INTO token_buckets (storage_key, bucket_key, count, refilled_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?)",
			l.storageKey,
			key,
			l.max-cost,
			nowMs,
			nowMs,
		)
		if err != nil {
			return false, err
		}

		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return false, err
		}
		committed = true
		return true, nil
	}
	if err != nil {
		return false, err
	}

	if count < 0 {
		count = 0
	}
	if count > l.max {
		count = l.max
	}

	if nowMs > refilledAtMs {
		refill := (nowMs - refilledAtMs) / l.refillIntervalMs
		if refill > 0 {
			count += refill
			if count > l.max {
				count = l.max
			}
			refilledAtMs += refill * l.refillIntervalMs
		}
	}

	allowed := count >= cost
	if allowed {
		count -= cost
	}

	_, err = conn.ExecContext(
		ctx,
		"UPDATE token_buckets SET count = ?, refilled_at_ms = ?, updated_at_ms = ? WHERE storage_key = ? AND bucket_key = ?",
		count,
		refilledAtMs,
		nowMs,
		l.storageKey,
		key,
	)
	if err != nil {
		return false, err
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return false, err
	}
	committed = true

	return allowed, nil
}

func (l *TokenBucket) PruneIdle(ctx context.Context, maxIdle time.Duration) error {
	if l == nil {
		return errors.New("ratelimit limiter is nil")
	}
	if maxIdle <= 0 {
		return nil
	}

	cutoffMs := l.now().UTC().Add(-maxIdle).UnixMilli()
	_, err := l.db.ExecContext(
		ctx,
		"DELETE FROM token_buckets WHERE storage_key = ? AND updated_at_ms < ?",
		l.storageKey,
		cutoffMs,
	)
	return err
}

func (l *TokenBucket) StartCleanup(interval, maxIdle time.Duration) func() {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	if maxIdle <= 0 {
		maxIdle = 1 * time.Hour
	}

	ticker := time.NewTicker(interval)
	done := make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				_ = l.PruneIdle(context.Background(), maxIdle)
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	return func() {
		close(done)
	}
}

func (l *TokenBucket) String() string {
	return fmt.Sprintf("sqlite-token-bucket[%s,max=%d,refill_ms=%d]", l.storageKey, l.max, l.refillIntervalMs)
}
