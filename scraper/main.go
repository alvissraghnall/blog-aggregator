package main

import (
	"fmt"
	"log"
	"scraper/services/rabbitmq"

	"github.com/joho/godotenv"
	"github.com/robfig/cron/v3"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	rabbitmq.NewRabbitMQConnection()
}

func FetchAndAddToMQ() {
	raw_content_queue := "raw_content"
	err := rabbitmq.RabbitMQClient.FetchFeed(raw_content_queue)
	if err != nil {

		log.Fatal("Error fetching and adding to queue!")
	}
	fmt.Println("SUCCESS!")
	return
}

func main() {

	defer rabbitmq.RabbitMQClient.CloseConnection()

	c := cron.New()

	c.AddFunc("* * * * *", FetchAndAddToMQ)

	c.Run()

	FetchAndAddToMQ()

	fmt.Println("done")
}
