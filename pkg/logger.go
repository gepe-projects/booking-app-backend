package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"booking-app/pkg/config"

	"github.com/sirupsen/logrus"
)

var Log = logrus.New()

func Init(cfg *config.AppConfig) {
	Log.SetOutput(os.Stdout)

	switch strings.ToLower(cfg.AppEnv) {
	case "dev", "development":
		Log.SetLevel(logrus.DebugLevel)
		Log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			ForceColors:     true,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				return fmt.Sprintf("%s:%d", f.File, f.Line), filepath.Base(f.File)
			},
		})
		Log.SetReportCaller(true) // Penting untuk debugging di development
	case "prod", "production":
		Log.SetLevel(logrus.InfoLevel) // Info atau WarnLevel untuk production
		Log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00", // Format ISO 8601 untuk log aggregator
		})
		Log.SetReportCaller(true) // Tetap aktifkan caller di production, ini sangat membantu debugging di sistem terdistribusi
	default:
		// Default untuk environment lain atau jika tidak terdefinisi
		Log.SetLevel(logrus.InfoLevel)
		Log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
		})
		Log.SetReportCaller(true)
	}

	Log.SetLevel(logrus.InfoLevel)
}
