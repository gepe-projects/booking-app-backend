package db

import (
	logger "booking-app/pkg"
	"booking-app/pkg/config"
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// konek db
func PostgresDB(ctx context.Context, config *config.AppConfig) *pgxpool.Pool {
	dbUrl := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", config.DB.User, config.DB.Password, config.DB.Host, config.DB.Port, config.DB.Name)
	pool, err := pgxpool.New(ctx, dbUrl)
	if err != nil {
		panic(err)
	}

	pool.Config().MaxConns = int32(config.DB.MaxOpenConns)
	pool.Config().MaxConnLifetime = config.DB.ConnMaxLifetime
	pool.Config().MinConns = 2
	if err := pool.Ping(ctx); err != nil {
		logger.Log.Errorf("failed to ping database: %v", err)
		panic(err)
	}
	logger.Log.Info("connected to database")
	return pool
}
