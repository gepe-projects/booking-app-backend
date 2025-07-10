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

	authHandler "booking-app/internal/auth/handler"
	authRepo "booking-app/internal/auth/repository"
	authService "booking-app/internal/auth/service"
	logger "booking-app/pkg"
	"booking-app/pkg/config"
	"booking-app/pkg/helper"
	middlewares "booking-app/pkg/middleware"
	"booking-app/pkg/util"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// load config
	cfg := config.LoadConfig()

	// logger
	logger.Init(cfg)

	// helper
	passwordHasher := helper.NewPasswordHasher(bcrypt.DefaultCost)

	// utils
	tokenManager, err := util.NewTokenManager(cfg.JWT.PrivateKeyPath, cfg.JWT.PublicKeyPath, cfg.JWT.SessionExpiration)
	if err != nil {
		logger.Log.Errorf("failed to create token manager: %v", err)
		os.Exit(1)
	}

	// validator
	validator := validator.New()

	// database and store
	dbPool := db.PostgresDB(context.Background(), cfg)
	store := db.NewStore(dbPool)

	// repository
	userRepository := userRepo.NewUserRepository(store)
	authRepository := authRepo.NewAuthRepository(store)

	// service
	userService := userService.NewUserService(userRepository)
	authService := authService.NewAuthService(authRepository, userRepository, passwordHasher, tokenManager, cfg)

	// middleware
	mw := middlewares.NewMiddleware(tokenManager)

	// handler
	authHandler := authHandler.NewAuthRoutes(mw, validator, authService)
	userHandler := userHandler.NewUserRoutes(mw, validator, userService)

	// setup router
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Group(func(r chi.Router) {
		r.Route("/api/v1", func(r chi.Router) {
			authHandler.MountAuthRoutes(r)
			userHandler.MountUserRoutes(r)
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
