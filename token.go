package boltdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/boltdb/bolt"
	"github.com/satori/go.uuid"

	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/models"
)

// NewTokenStore creates a token store based on boltdb
func NewTokenStore(config *Config) (oauth2.TokenStore, func(), error) {
	db, err := bolt.Open(config.DbName, 0600, nil)

	if err != nil {
		return nil, nil, err
	}

	bucketTtlName := []byte(fmt.Sprintf("%s-ttl", config.BucketName))
	bucketName := []byte(config.BucketName)

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketName)

		if err != nil {
			return err
		}

		_, err = tx.CreateBucketIfNotExists(bucketTtlName)

		return err
	})

	if err != nil {
		return nil, nil, err
	}

	ts := &TokenStore{
		db:            db,
		bucketName:    bucketName,
		bucketTtlName: bucketTtlName,
	}

	tsc := &TokenStoreCleaner{
		db:            db,
		quit:          make(chan struct{}),
		bucketName:    bucketName,
		bucketTtlName: bucketTtlName,
	}

	tsc.monitor()

	closeFunction := func() {
		tsc.close()
		db.Close()
	}

	return ts, closeFunction, nil
}

// TokenStore token storage based on boltdb(https://github.com/boltdb/bolt)
type TokenStore struct {
	db            *bolt.DB
	bucketName    []byte
	bucketTtlName []byte
}

// createTtl creates an entry on the TTL bucket.
func createTtl(bucket *bolt.Bucket, key []byte, ttl time.Duration) error {
	expirationTime := time.Now().Add(ttl).UTC().Format(time.RFC3339Nano)

	return bucket.Put([]byte(expirationTime), key)
}

// Create creates and store the new token information
func (ts *TokenStore) Create(info oauth2.TokenInfo) error {
	ct := time.Now()
	jv, err := json.Marshal(info)
	if err != nil {
		return err
	}

	return ts.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(ts.bucketName)
		ttlBucket := tx.Bucket(ts.bucketTtlName)

		if code := info.GetCode(); code != "" {
			byteCode := []byte(code)
			err := bucket.Put(byteCode, jv)

			if err != nil {
				return err
			}

			return createTtl(ttlBucket, byteCode, info.GetCodeExpiresIn())
		}

		basicID := uuid.NewV4().Bytes()
		aexp := info.GetAccessExpiresIn()
		rexp := aexp

		if refresh := info.GetRefresh(); refresh != "" {
			rexp = info.GetRefreshCreateAt().Add(info.GetRefreshExpiresIn()).Sub(ct)
			if aexp.Seconds() > rexp.Seconds() {
				aexp = rexp
			}

			byteRefresh := []byte(refresh)
			err := bucket.Put(byteRefresh, basicID)
			if err != nil {
				return nil
			}

			return createTtl(ttlBucket, byteRefresh, rexp)
		}

		err := bucket.Put(basicID, jv)
		if err != nil {
			return nil
		}

		err = createTtl(ttlBucket, basicID, rexp)
		if err != nil {
			return nil
		}

		byteAccess := []byte(info.GetAccess())

		err = bucket.Put(byteAccess, basicID)
		if err != nil {
			return nil
		}

		return createTtl(ttlBucket, byteAccess, aexp)
	})
}

// remove key
func (ts *TokenStore) remove(key string) error {
	return ts.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(ts.bucketName)
		// TODO: TTL

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
		bucket := tx.Bucket(ts.bucketName)

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
		bucket := tx.Bucket(ts.bucketName)

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

// TokenStoreCleaner is in charge of cleaning keys with expired ttl
type TokenStoreCleaner struct {
	db            *bolt.DB
	quit          chan struct{}
	bucketName    []byte
	bucketTtlName []byte
}

// monitor is the start method and will create a monitor that will sweep every minute
func (tsc *TokenStoreCleaner) monitor() {
	ticker := time.NewTicker(30 * time.Second)

	go tsc.dispatcher(ticker)
}

// close is the close method for the monitor
func (tsc *TokenStoreCleaner) close() {
	tsc.quit <- struct{}{}
}

// dispatcher will receive close or tick calls and perform the required actions
func (tsc *TokenStoreCleaner) dispatcher(ticker *time.Ticker) {
	for {
		select {
		case <-ticker.C:
			tsc.sweep()

		case <-tsc.quit:
			ticker.Stop()
			return
		}
	}
}

// sweep scans the ttl bucket searching for expired keys
func (tsc *TokenStoreCleaner) sweep() error {
	keys, ttlKeys, err := tsc.getExpired()

	if err != nil || len(keys) == 0 {
		return nil
	}

	return tsc.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(tsc.bucketName)
		ttlBucket := tx.Bucket(tsc.bucketTtlName)

		for _, key := range keys {
			bucket.Delete(key)
		}

		for _, key := range ttlKeys {
			ttlBucket.Delete(key)
		}

		return nil
	})
}

func (tsc *TokenStoreCleaner) getExpired() ([][]byte, [][]byte, error) {
	keys := [][]byte{}
	ttlKeys := [][]byte{}

	err := tsc.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(tsc.bucketTtlName).Cursor()

		max := []byte(time.Now().UTC().Format(time.RFC3339Nano))

		for k, v := c.First(); k != nil && bytes.Compare(k, max) <= 0; k, v = c.Next() {
			keys = append(keys, v)
			ttlKeys = append(ttlKeys, k)
		}

		return nil
	})

	return keys, ttlKeys, err
}
