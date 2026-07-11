package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const DisabledPasswordValue = "__frp_control_disabled_password__"

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func NewOpaqueToken(prefix string) (plain string, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	plain = prefix + base64.RawURLEncoding.EncodeToString(raw)
	return plain, TokenHash(plain), nil
}

func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TokenPrefix(token string) string {
	if len(token) <= 12 {
		return token
	}
	return token[:12]
}

func NewAdminBrowserToken(userID int64, adminTokenHash, secret string, ttl time.Duration) (string, time.Time, error) {
	nonceRaw := make([]byte, 16)
	if _, err := rand.Read(nonceRaw); err != nil {
		return "", time.Time{}, err
	}
	now := time.Now()
	expires := now.Add(ttl)
	nonce := base64.RawURLEncoding.EncodeToString(nonceRaw)
	body := fmt.Sprintf("adm:%d:%d:%d:%s", userID, now.Unix(), expires.Unix(), nonce)
	sig := adminBrowserSignature(body, adminTokenHash, secret)
	token := "ast_" + base64.RawURLEncoding.EncodeToString([]byte(body+":"+sig))
	return token, expires, nil
}

func AdminBrowserTokenUserID(value string) (int64, error) {
	parts, err := decodeAdminBrowserToken(value)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(parts[1], 10, 64)
}

func ParseAdminBrowserToken(value, adminTokenHash, secret string) (int64, time.Time, error) {
	parts, err := decodeAdminBrowserToken(value)
	if err != nil {
		return 0, time.Time{}, err
	}
	body := strings.Join(parts[:5], ":")
	expected := adminBrowserSignature(body, adminTokenHash, secret)
	if !hmac.Equal([]byte(expected), []byte(parts[5])) {
		return 0, time.Time{}, errors.New("invalid admin token signature")
	}
	userID, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, time.Time{}, err
	}
	expiresUnix, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return 0, time.Time{}, err
	}
	expiresAt := time.Unix(expiresUnix, 0)
	if time.Now().After(expiresAt) {
		return 0, time.Time{}, errors.New("admin token expired")
	}
	return userID, expiresAt, nil
}

func decodeAdminBrowserToken(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "ast_") {
		return nil, errors.New("invalid admin token prefix")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, "ast_"))
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 6 || parts[0] != "adm" {
		return nil, errors.New("invalid admin token format")
	}
	return parts, nil
}

func adminBrowserSignature(body, adminTokenHash, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret+":"+adminTokenHash))
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func SignSession(secret string, userID int64, ttl time.Duration) string {
	expires := time.Now().Add(ttl).Unix()
	body := fmt.Sprintf("%d:%d", userID, expires)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(body + ":" + sig))
}

func ParseSession(secret, value string) (int64, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return 0, err
	}
	parts := strings.Split(string(decoded), ":")
	if len(parts) != 3 {
		return 0, errors.New("invalid session format")
	}
	body := parts[0] + ":" + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return 0, errors.New("invalid session signature")
	}
	expires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, err
	}
	if time.Now().Unix() > expires {
		return 0, errors.New("session expired")
	}
	return strconv.ParseInt(parts[0], 10, 64)
}
