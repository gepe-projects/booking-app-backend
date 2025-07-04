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
	GenerateCSRFToken(userID uuid.UUID) (string, jwt.RegisteredClaims, error)
	ParseCSRFToken(token string, userID uuid.UUID) bool
	GetPublicKey() *rsa.PublicKey
}

type CustomClaims struct {
	UserID string         `json:"uid"`
	Email  string         `json:"email"`
	Role   string         `json:"role"`
	Extra  map[string]any `json:"extra,omitempty"` // opsional
	jwt.RegisteredClaims
}

type jwtManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	accessTTL  time.Duration
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

func (jm *jwtManager) GenerateCSRFToken(userID uuid.UUID) (string, jwt.RegisteredClaims, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Subject:   userID.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(jm.accessTTL)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(jm.privateKey)

	return tokenString, claims, err
}

func (jm *jwtManager) ParseCSRFToken(tokenStr string, userID uuid.UUID) bool {
	token, err := jwt.ParseWithClaims(tokenStr, &jwt.RegisteredClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			logger.Log.Errorf("ATTACK ALLERT CSRF: unexpected signing method in csrf: %v", t.Header["alg"])
			return nil, jwt.ErrSignatureInvalid
		}
		return jm.publicKey, nil
	})
	if err != nil {
		logger.Log.Errorf("ATTACK ALLERT CSRF: failed to parse csrf token: %v", err)
		return false
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		if claims.Subject != userID.String() {
			logger.Log.Errorf("ATTACK ALLERT CSRF: userID mismatch: %v", err)
			return false
		}
		return true
	}

	return false
}

// GetPublicKey mengembalikan public key, digunakan untuk verifikasi token dari service lain atau frontend
func (jm *jwtManager) GetPublicKey() *rsa.PublicKey {
	return jm.publicKey
}
