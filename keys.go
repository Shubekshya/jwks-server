package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var randReader io.Reader = rand.Reader

type Key struct {
	KID        string
	PrivateKey *rsa.PrivateKey
	ExpiresAt  time.Time
}

type KeyStore struct {
	db *sql.DB
}

const databasePath = "totally_not_my_privateKeys.db"

func NewKeyStore() (*KeyStore, error) {
	return OpenKeyStore(databasePath)
}

func OpenKeyStore(path string) (*KeyStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	ks := &KeyStore{db: db}
	if err = ks.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return ks, nil
}

func (ks *KeyStore) Close() error {
	return ks.db.Close()
}

func (ks *KeyStore) initialize() error {
	schema := `CREATE TABLE IF NOT EXISTS keys(
		kid INTEGER PRIMARY KEY AUTOINCREMENT,
		key BLOB NOT NULL,
		exp INTEGER NOT NULL
	)`
	if _, err := ks.db.Exec(schema); err != nil {
		return fmt.Errorf("create keys table: %w", err)
	}

	now := time.Now()
	for _, expired := range []bool{false, true} {
		var count int
		query := "SELECT COUNT(*) FROM keys WHERE exp > ?"
		expiry := now.Add(2 * time.Hour)
		threshold := now.Unix()
		if expired {
			query = "SELECT COUNT(*) FROM keys WHERE exp <= ?"
			expiry = now.Add(-1 * time.Hour)
			threshold = now.Unix()
		}
		if err := ks.db.QueryRow(query, threshold).Scan(&count); err != nil {
			return fmt.Errorf("check key count: %w", err)
		}
		if count == 0 {
			key, err := generateKey(expiry)
			if err != nil {
				return fmt.Errorf("generate initial key: %w", err)
			}
			if _, err := ks.saveKey(key); err != nil {
				return fmt.Errorf("save initial key: %w", err)
			}
		}
	}
	return nil
}

func generateKey(expiresAt time.Time) (Key, error) {
	priv, err := rsa.GenerateKey(randReader, 2048)
	if err != nil {
		return Key{}, fmt.Errorf("generate rsa key: %w", err)
	}
	return Key{
		PrivateKey: priv,
		ExpiresAt:  expiresAt,
	}, nil
}

func (ks *KeyStore) saveKey(key Key) (string, error) {
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key.PrivateKey),
	})
	result, err := ks.db.Exec("INSERT INTO keys(key, exp) VALUES(?, ?)", data, key.ExpiresAt.Unix())
	if err != nil {
		return "", fmt.Errorf("insert key: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return "", fmt.Errorf("last insert id: %w", err)
	}
	return strconv.FormatInt(id, 10), nil
}

func decodeKey(id int64, data []byte, exp int64) (Key, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return Key{}, fmt.Errorf("invalid private key pem for kid %d", id)
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return Key{}, fmt.Errorf("parse private key: %w", err)
	}
	return Key{
		KID:        strconv.FormatInt(id, 10),
		PrivateKey: priv,
		ExpiresAt:  time.Unix(exp, 0),
	}, nil
}

func (ks *KeyStore) signingKey(expired bool, now time.Time) (Key, error) {
	query := "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC, kid DESC LIMIT 1"
	if expired {
		query = "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC, kid DESC LIMIT 1"
	}
	var id, exp int64
	var data []byte
	if err := ks.db.QueryRow(query, now.Unix()).Scan(&id, &data, &exp); err != nil {
		return Key{}, fmt.Errorf("query signing key: %w", err)
	}
	return decodeKey(id, data, exp)
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func toJWK(k Key) JWK {
	pub := k.PrivateKey.PublicKey
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	if len(eBytes) == 0 {
		eBytes = []byte{0}
	}
	return JWK{
		Kty: "RSA",
		Kid: k.KID,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}
}

func (ks *KeyStore) unexpiredJWKS(now time.Time) (JWKS, error) {
	result := JWKS{Keys: make([]JWK, 0)}
	rows, err := ks.db.Query("SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY kid", now.Unix())
	if err != nil {
		return result, fmt.Errorf("query unexpired keys: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id, exp int64
		var data []byte
		if err := rows.Scan(&id, &data, &exp); err != nil {
			return result, fmt.Errorf("scan key: %w", err)
		}
		key, err := decodeKey(id, data, exp)
		if err != nil {
			return result, err
		}
		result.Keys = append(result.Keys, toJWK(key))
	}
	return result, rows.Err()
}
