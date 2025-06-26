package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type AppConfig struct {
	AppEnv   string
	AppPort  string
	GRPCPort string
	LogLevel string
	DB       DBConfig
	JWT      JWTConfig
	Redis    RedisConfig
	Kafka    KafkaConfig
}

type DBConfig struct {
	Host            string
	Port            string
	User            string
	Password        string
	Name            string
	MaxOpenConns    int
	ConnMaxLifetime time.Duration
}

type JWTConfig struct {
	PrivateKeyPath string
	PublicKeyPath  string
}

type RedisConfig struct {
	Addr string
}

type KafkaConfig struct {
	Brokers []string
}

func LoadConfig() *AppConfig {
	_ = godotenv.Load()

	cfg := &AppConfig{
		AppEnv:   getEnv("APP_ENV", "development"),
		AppPort:  getEnv("APP_PORT", "8080"),
		GRPCPort: getEnv("APP_GRPC_PORT", "8081"),
		LogLevel: getEnv("LOG_LEVEL", "info"),

		DB: DBConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnv("DB_PORT", "5432"),
			User:            getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASSWORD", ""),
			Name:            getEnv("DB_NAME", "app"),
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 300*time.Second),
		},

		JWT: JWTConfig{
			PrivateKeyPath: getEnv("JWT_PRIVATE_KEY_PATH", "key/private.pem"),
			PublicKeyPath:  getEnv("JWT_PUBLIC_KEY_PATH", "key/public.pem"),
		},

		Redis: RedisConfig{
			Addr: getEnv("REDIS_ADDR", "localhost:6379"),
		},

		Kafka: KafkaConfig{
			Brokers: strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ","),
		},
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	if valStr := os.Getenv(key); valStr != "" {
		if val, err := strconv.Atoi(valStr); err == nil {
			return val
		}
	}
	return fallback
}

func getEnvAsDuration(key string, fallback time.Duration) time.Duration {
	if valStr := os.Getenv(key); valStr != "" {
		if valInt, err := strconv.Atoi(valStr); err == nil {
			return time.Duration(valInt) * time.Second
		}
	}
	return fallback
}
