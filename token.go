package boltdb

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/boltdb/bolt"
	"github.com/satori/go.uuid"

	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
)

// NewTokenStore creates a token store based on boltdb
func NewTokenStore(config *Config) (oauth2.TokenStore, *bolt.DB, error) {
	db, err := bolt.Open(config.DbName, 0600, nil)

	if err != nil {
		return nil, nil, err
	}

	bucketTtlName := fmt.Sprintf("%s-ttl", config.BucketName)

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(config.BucketName))

		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists([]byte(bucketTtlName))

		return err
	})

	if err != nil {
		return nil, nil, err
	}

	return &TokenStore{
		db:            db,
		bucketName:    config.BucketName,
		bucketTtlName: bucketTtlName,
	}, db, nil
}

// TokenStore token storage based on boltdb(https://github.com/boltdb/bolt)
type TokenStore struct {
	db            *bolt.DB
	bucketName    string
	bucketTtlName string
}

// Create creates and store the new token information
func (ts *TokenStore) Create(info oauth2.TokenInfo) error {
	ct := time.Now()
	jv, err := json.Marshal(info)
	if err != nil {
		return err
	}

	return ts.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(ts.bucketName))
		//TODO: TTL bucket

		if code := info.GetCode(); code != "" {
			return bucket.Put([]byte(code), jv) // TODO: code to byte?
			// TODO: TTL!
		}

		basicID := uuid.NewV4().Bytes()
		// TODO: This ttls are in seconds but we will need to save the time WHEN they expire.. (ttl + ct)
		aexp := info.GetAccessExpiresIn()
		rexp := aexp

		if refresh := info.GetRefresh(); refresh != "" {
			rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Sub(ct)
			if aexp.Seconds() > rexp.Seconds() {
				aexp = rexp
			}

			err := bucket.Put([]byte(refresh), basicID)
			// TODO: TTL

			if err != nil {
				return nil
			}
		}

		err := bucket.Put(basicID, jv) // TODO: TTL

		if err != nil {
			return nil
		}

		return bucket.Put([]byte(info.GetAccess()), basicID) // TODO: TTL
	})
}

// remove key
func (ts *TokenStore) remove(key string) error {
	return ts.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(ts.bucketName))
		// TODO: TTL

		// TODO: key to byte?
		return bucket.Delete([]byte(key))
	})
}

// RemoveByCode use the authorization code to delete the token information
func (ts *TokenStore) RemoveByCode(code string) error {
	return ts.remove(code)
}

// RemoveByAccess use the access token to delete the token information
func (ts *TokenStore) RemoveByAccess(access string) error {
	return ts.remove(access)
}

// RemoveByRefresh use the refresh token to delete the token information
func (ts *TokenStore) RemoveByRefresh(refresh string) error {
	return ts.remove(refresh)
}

func (ts *TokenStore) getData(key string) (oauth2.TokenInfo, error) {
	var tm models.Token

	err := ts.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(ts.bucketName))

		jv := bucket.Get([]byte(key))

		return json.Unmarshal(jv, &tm)
	})

	if err != nil {
		return nil, err
	}

	return &tm, nil
}

func (ts *TokenStore) getBasicID(key string) string {
	var basicId []byte

	ts.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(ts.bucketName))

		basicId = bucket.Get([]byte(key))
		return nil
	})

	return string(basicId)
}

// GetByCode use the authorization code for token information data
func (ts *TokenStore) GetByCode(code string) (oauth2.TokenInfo, error) {
	return ts.getData(code)
}

// GetByAccess use the access token for token information data
func (ts *TokenStore) GetByAccess(access string) (oauth2.TokenInfo, error) {
	basicID := ts.getBasicID(access)
	return ts.getData(basicID)
}

// GetByRefresh use the refresh token for token information data
func (ts *TokenStore) GetByRefresh(refresh string) (oauth2.TokenInfo, error) {
	basicID := ts.getBasicID(refresh)
	return ts.getData(basicID)
}
