# BoltDB Storage for OAuth 2.0

A BoltDB token storage for the [go-oauth2](https://github.com/go-oauth2) package

## Install

```
$ go get -u github.com/naxhh/go-oauth2-boltdb
```

## Usage

```
tokenStore, close, err := boltdb.NewTokenStore(&boltdb.Config{
  DbName:     "oauth2.db",
  BucketName: "oauthTokens",
})

manager := manage.NewDefaultManager()
manager.MustTokenStorage(tokenStore, err)
defer close() // This ensure the DB is closed correctly
```

## Internals

BoltDB is a low level database, so its out of the scope the implementation of TTL's
go-oauth2 relies on the TTL implementations to ensure the correct deletion of the tokens.

This means this package also contains a TTL implementation over boltdb to ensure TTL's are correctly deleted

The approach is to create a bucket that will be called `tsc.BucketName + "-ttl"`
This bucket will contain all the entries that have a TTL and when they should be deleted.

The key of the entry is when it should be deleted and the value the key to be deleted.
A monitor will be executed every minut to ensure all the keys are deleted.

Currently the system has a low precision 2 runs every minute is very low

But since this package is used mainly for side projects that is not a problem at all.
In case you need more precision ensure to open a PR that allow configurable sweep durations
