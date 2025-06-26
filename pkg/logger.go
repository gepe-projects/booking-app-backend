package logger

import (
	"os"

	"booking-app/pkg/config"

	"github.com/sirupsen/logrus"
)

var Log = logrus.New()

func Init(cfg *config.AppConfig) {
	Log.SetOutput(os.Stdout)

	if cfg.AppEnv == "prod" || cfg.AppEnv == "production" {
		Log.SetFormatter(&logrus.JSONFormatter{})
	} else {
		Log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})
	}

	Log.SetLevel(logrus.InfoLevel)
}
