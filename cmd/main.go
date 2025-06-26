package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	db "booking-app/internal/db/sqlc"
	userHandler "booking-app/internal/user/handler"
	userRepo "booking-app/internal/user/repository"
	userService "booking-app/internal/user/service"
	logger "booking-app/pkg"
	"booking-app/pkg/config"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
)

func main() {
	// load config
	cfg := config.LoadConfig()

	// logger
	logger.Init(cfg)

	// validator
	validator := validator.New()

	// database and store
	dbPool := db.PostgresDB(context.Background(), cfg)
	store := db.NewStore(dbPool)

	// repository
	userRepository := userRepo.NewUserRepository(store)

	// service
	userService := userService.NewUserService(userRepository)

	// setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Group(func(r chi.Router) {
		r.Route("/api/v1", func(r chi.Router) {
			// register routes
			userHandler.RegisterUserRoutes(r, userHandler.NewUserHandler(validator, userService))
		})
	})

	addr := fmt.Sprintf(":%s", cfg.AppPort)
	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}
	// graceful shutdown
	idleConnsClosed := make(chan struct{})
	go func() {
		// lister sinyal termination
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)

		<-sigint // block semua kode di bawah ini sampai mendapatkan sinyal termination
		logger.Log.Info("shutting down server...")

		// context timeout 20detik
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()

		// shutdown server
		if err := srv.Shutdown(ctx); err != nil {
			logger.Log.Fatalf("failed to shutdown server: %v", err)
		}
		dbPool.Close()
		close(idleConnsClosed)
	}()

	// run server
	logger.Log.Infof("🚀 starting server on port %s", cfg.AppPort)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		logger.Log.Fatalf("failed to listen and serve: %v", err)
	}

	<-idleConnsClosed // tunggu shutdown server selsai
	logger.Log.Info("Server shutdown complete.")
}
