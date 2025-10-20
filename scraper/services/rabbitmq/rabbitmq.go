package rabbitmq

import (
	"fmt"
	"log"
	"os"

	"github.com/go-zoox/fetch"
	amqp "github.com/rabbitmq/amqp091-go"
)

func failOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
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

func (r *RabbitMQ) FetchFeed(raw_content_queue string) error {
	response, err := fetch.Get("https://www.30secondsofcode.org/feed")
	if err != nil {
		failOnError(err, "Failed to fetch feed: %s")
	}
	q, err := r.Channel.QueueDeclare(
		raw_content_queue, // queue name
		true,              // durable
		false,             // delete when unused
		false,             // exclusive
		false,             // no-wait
		nil,               // arguments
	)
	if err != nil {
		failOnError(err, "Failed to declare queue: %s")
	}

	err = r.Channel.Publish(
		"",     // exchange
		q.Name, // routing key (queue name)
		false,  // mandatory
		false,  // immediate
		amqp.Publishing{
			ContentType: "raw",
			Body:        response.Body,
		})

	if err != nil {
		return fmt.Errorf("failed to publish message: %v", err)
	}

	log.Printf("RSS Feed has been sent to RabbitMQ queue: %s", string(response.Body[:]))

	return nil

}
