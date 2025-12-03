package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"scraper/services/rabbitmq"
	"time"

	"github.com/joho/godotenv"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
)

type RSSConfig struct {
	RSSFeeds      map[string][]string `json:"rss_feeds"`
	ScraperConfig ScraperConfig       `json:"scraper_config"`
}

type ScraperConfig struct {
	FetchIntervalMinutes int    `json:"fetch_interval_minutes"`
	QueueName            string `json:"queue_name"`
	MaxRetries           int    `json:"max_retries"`
	TimeoutSeconds       int    `json:"timeout_seconds"`
}

type FeedMessage struct {
	FeedURL    string `json:"feed_url"`
	RawContent string `json:"raw_content"`
}

var config RSSConfig
var q amqp.Queue
var rdb redis.Client
var ctx = context.Background()

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	configFile, err := os.ReadFile("rss_feeds_config.json")
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}

	rabbitmq.NewRabbitMQConnection()

	q = rabbitmq.RabbitMQClient.DeclareQueue(config.ScraperConfig.QueueName)

	redisHost := os.Getenv("REDIS_HOST")
	redisPort := os.Getenv("REDIS_PORT")

	rdb = *redis.NewClient(&redis.Options{
		Addr:     redisHost + ":" + redisPort,
		Username: os.Getenv("REDIS_USERNAME"),
		Password: os.Getenv("REDIS_PASSWORD"),
	})

	_, err = rdb.Ping(ctx).Result()
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	log.Println("Successfully connected to Redis.")

}

// func FetchAndAddToMQ() {
// 	raw_content_queue := "raw_content"
// 	err := rabbitmq.RabbitMQClient.FetchFeed(raw_content_queue)
// 	if err != nil {

// 		log.Fatal("Error fetching and adding to queue!")
// 	}
// 	fmt.Println("SUCCESS!")
// 	return
// }

func getAllFeedURLs(feeds map[string][]string) []string {
	var allURLs []string
	for _, categoryFeeds := range feeds {
		allURLs = append(allURLs, categoryFeeds...)
	}
	return allURLs
}

func main() {

	defer rabbitmq.RabbitMQClient.CloseConnection()

	client := &http.Client{
		Timeout: time.Duration(config.ScraperConfig.TimeoutSeconds) * time.Second,
	}

	ticker := time.NewTicker(time.Duration(config.ScraperConfig.FetchIntervalMinutes) * time.Minute)
	defer ticker.Stop()

	log.Printf("Scraper started. Will fetch feeds every %d minutes.", config.ScraperConfig.FetchIntervalMinutes)

	for range ticker.C {
		log.Println("Ticker fired: Starting new scrape cycle...")
		allFeeds := getAllFeedURLs(config.RSSFeeds)
		for _, feedURL := range allFeeds {
			rabbitmq.RabbitMQClient.FetchFeed(client, &rdb, ctx, q.Name, feedURL)
		}
		log.Println("Scrape cycle finished. Waiting for next tick.")
	}

	fmt.Println("done")
}
