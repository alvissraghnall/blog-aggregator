package rabbitmq

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/redis/go-redis/v9"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

type FeedMessage struct {
	FeedURL    string `json:"feed_url"`
	RawContent string `json:"raw_content"`
}

var RabbitMQClient *RabbitMQ

type RabbitMQ struct {
	Conn    *amqp.Connection
	Channel *amqp.Channel
}

func NewRabbitMQConnection() {

	conn, err := amqp.Dial(os.Getenv("RABBITMQ_CONNECTION_URL"))
	failOnError(err, "Failed to connect to RabbitMQ")

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Failed to open a RabbitMQ channel: %s", err)
	}

	RabbitMQClient = &RabbitMQ{
		Conn:    conn,
		Channel: ch,
	}
}

func (r *RabbitMQ) CloseConnection() {
	r.Channel.Close()
	r.Conn.Close()
}

func (r *RabbitMQ) DeclareQueue(queueName string) amqp.Queue {
	q, err := r.Channel.QueueDeclare(
		queueName, // queue name
		true,      // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		failOnError(err, "Failed to declare queue: %s")
	}
	return q
}

func (r *RabbitMQ) FetchFeed(client *http.Client, rdb *redis.Client, ctx context.Context, queueName, feedURL string) error {

	log.Printf("Fetching feed: %s", feedURL)

	etagKey := fmt.Sprintf("etag:%s", feedURL)
	modifiedKey := fmt.Sprintf("modified:%s", feedURL)

	lastETag, err := rdb.Get(ctx, etagKey).Result()
	if err != nil && err != redis.Nil {
		log.Printf("Redis error getting ETag for %s: %v", feedURL, err)
		return err
	}
	lastModified, err := rdb.Get(ctx, modifiedKey).Result()
	if err != nil && err != redis.Nil {
		log.Printf("Redis error getting Last-Modified for %s: %v", feedURL, err)
		return err
	}

	req, err := http.NewRequest("GET", feedURL, nil)
	if err != nil {
		log.Printf("Error creating request for %s: %v", feedURL, err)
		return err
	}

	if lastETag != "" {
		req.Header.Add("If-None-Match", lastETag)
	}
	if lastModified != "" {
		req.Header.Add("If-Modified-Since", lastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error fetching feed %s: %v", feedURL, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		log.Printf("Feed unchanged (304 Not Modified): %s", feedURL)
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Received non-200 status code %d for %s", resp.StatusCode, feedURL)
		return nil
	}

	log.Printf("Feed has changed.. fetching content for: %s", feedURL)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response body for %s: %v", feedURL, err)
		return err
	}

	message := FeedMessage{
		FeedURL:    feedURL,
		RawContent: string(bodyBytes),
	}
	messageBody, err := json.Marshal(message)
	if err != nil {
		log.Printf("Error marshaling message for %s: %v", feedURL, err)
		return err
	}

	err = r.Channel.Publish(
		"",
		queueName,
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        messageBody,
		},
	)
	if err != nil {
		log.Printf("Error publishing message to queue for %s: %v", feedURL, err)
		return err
	}

	newETag := resp.Header.Get("ETag")
	newModified := resp.Header.Get("Last-Modified")

	if newETag != "" {
		err = rdb.Set(ctx, etagKey, newETag, 0).Err()
		if err != nil {
			log.Printf("Failed to cache new ETag for %s: %v", feedURL, err)
		}
	}
	if newModified != "" {
		err = rdb.Set(ctx, modifiedKey, newModified, 0).Err()
		if err != nil {
			log.Printf("Failed to cache new Last-Modified for %s: %v", feedURL, err)
		}
	}

	// resp, err := client.Get(feedURL)
	// if err != nil {
	// 	log.Printf("Error fetching feed %s: %v", feedURL, err)
	// 	return err
	// }
	// defer resp.Body.Close()

	// bodyBytes, err := io.ReadAll(resp.Body)
	// if err != nil {
	// 	log.Printf("Error reading response body for %s: %v", feedURL, err)
	// 	return err
	// }

	// message := FeedMessage{
	// 	FeedURL:    feedURL,
	// 	RawContent: string(bodyBytes),
	// }

	// messageBody, err := json.Marshal(message)
	// if err != nil {
	// 	log.Printf("Error marshaling message for %s: %v", feedURL, err)
	// 	return err
	// }

	// err = r.Channel.Publish(
	// 	"",        // exchange
	// 	queueName, // routing key (queue name)
	// 	false,     // mandatory
	// 	false,     // immediate
	// 	amqp.Publishing{
	// 		ContentType: "application/json",
	// 		Body:        messageBody,
	// 	})

	// if err != nil {
	// 	return fmt.Errorf("failed to publish message: %v", err)
	// }

	log.Printf("Successfully published raw feed content for: %s", feedURL)

	return nil

}
