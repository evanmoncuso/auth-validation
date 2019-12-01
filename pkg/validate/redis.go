package validate

import (
	"errors"
	"time"

	"github.com/gomodule/redigo/redis"
)

func connectToRedis(connectionURL string) *redis.Pool {
	return &redis.Pool{
		MaxIdle:     10,
		IdleTimeout: 240 * time.Second,
		Dial: func() (redis.Conn, error) {
			return redis.DialURL(connectionURL)
		},
	}
}

func checkForInvalidToken(t string) error {
	conn := InvalidTokenStore.Get()
	defer conn.Close()

	if exists, err := redis.Int(conn.Do("EXISTS", t)); err != nil {
		return err
	} else if exists == 1 {
		return errors.New("Token present in invalidation store")
	}

	return nil
}
