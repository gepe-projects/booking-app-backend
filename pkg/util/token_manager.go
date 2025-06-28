package util

import (
	"crypto/rsa"
	"errors"
	"os"
	"time"

	logger "booking-app/pkg"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenManager interface {
	GenerateAccessToken(claims CustomClaims) (string, *CustomClaims, error)
	ParseAccessToken(tokenStr string) (*CustomClaims, error)
	GenerateRefreshToken() string
}

type CustomClaims struct {
	UserID string         `json:"uid"`
	Email  string         `json:"email"`
	Role   string         `json:"role"`
	Extra  map[string]any `json:"extra,omitempty"` // opsional
	jwt.RegisteredClaims
}

type jwtManager struct {
	privateKey       *rsa.PrivateKey
	publicKey        *rsa.PublicKey
	accessTTL        time.Duration
	refreshAccessTTL time.Duration
}

func NewTokenManager(privateKeyPath, publicKeyPath string, accessTTL time.Duration) (tokenManager TokenManager, err error) {
	privBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		logger.Log.Errorf("failed to read private key: %v", err)
		return
	}
	pubBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		logger.Log.Errorf("failed to read public key: %v", err)
		return
	}

	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(privBytes)
	if err != nil {
		logger.Log.Errorf("failed to parse private key: %v", err)
		return
	}
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM(pubBytes)
	if err != nil {
		logger.Log.Errorf("failed to parse private key: %v", err)
		return
	}

	return &jwtManager{
		privateKey: privKey,
		publicKey:  pubKey,
		accessTTL:  accessTTL,
	}, nil
}

func (jm *jwtManager) GenerateAccessToken(claims CustomClaims) (string, *CustomClaims, error) {
	now := time.Now()
	claims.RegisteredClaims.IssuedAt = jwt.NewNumericDate(now)
	claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(now.Add(jm.accessTTL))

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	tokenString, err := token.SignedString(jm.privateKey)
	if err != nil {
		logger.Log.Errorf("failed to sign token: %v", err)
		return "", nil, err
	}

	return tokenString, &claims, nil
}

func (jm *jwtManager) ParseAccessToken(tokenStr string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &CustomClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			logger.Log.Errorf("unexpected signing method: %v", t.Header["alg"])
			return nil, jwt.ErrSignatureInvalid
		}
		return jm.publicKey, nil
	})
	if err != nil {
		logger.Log.Errorf("failed to parse token: %v", err)
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func (jm *jwtManager) GenerateRefreshToken() string {
	return uuid.NewString()
}
