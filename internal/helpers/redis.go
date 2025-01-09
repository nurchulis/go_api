package helpers

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/go-redis/redis/v8"
)

// Redis client initialization
var redisClient = redis.NewClient(&redis.Options{
	Addr: "localhost:6379", // Update this with your Redis server details
})

var ctx = context.Background()

// Get From Cache
func GetFromCache(cacheKey string, result interface{}) error {
	cachedData, err := redisClient.Get(ctx, cacheKey).Result()
	if err == nil {
		err := json.Unmarshal([]byte(cachedData), result)
		if err != nil {
			log.Println("Error unmarshalling cached data:", err)
		}
		return nil
	}
	return err
}

// SetToCache stores
func SetToCache(cacheKey string, data interface{}, ttl time.Duration) error {
	cacheData, err := json.Marshal(data)
	if err != nil {
		log.Println("Error marshalling data:", err)
		return err
	}
	err = redisClient.Set(ctx, cacheKey, cacheData, ttl).Err()
	if err != nil {
		log.Println("Error setting cache:", err)
		return err
	}
	return nil
}

// DelCache to delete cache
func DelCache(cacheKey string) error {

	err := redisClient.Del(ctx, cacheKey).Err()
	if err != nil {
		log.Println("Error setting cache:", err)
		return err
	}
	return nil
}
