package db

import (
	"context"
	"fmt"

	logger "booking-app/pkg"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Store interface {
	Querier
	// tambahkan method lain kalo di butuhin
	CreateUserWithMetadata(ctx context.Context, arg CreateuserWithMetadataParams) (CreateUserTxResult, error)
}

type store struct {
	*Queries
	db *pgxpool.Pool
}

func NewStore(db *pgxpool.Pool) Store {
	return &store{
		db:      db,
		Queries: New(db),
	}
}

func (s *store) ExecTx(ctx context.Context, fn func(*Queries) error) error {
	tx, err := s.db.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}

	q := New(tx)

	err = fn(q)
	if err != nil {
		if rollbackError := tx.Rollback(ctx); rollbackError != nil {
			logger.Log.Errorf("tx Error %v \n Rollback Error %v", err, rollbackError)
			return fmt.Errorf("tx Error %v \n Rollback Error %v", err, rollbackError)
		}
		return err
	}
	return tx.Commit(ctx)
}
