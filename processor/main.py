import os
import json
from dotenv import load_dotenv

from db.rabbitmq import get_rabbitmq_connection_and_channel
from db.mongo import get_mongo_collection
from services.article_fetcher import parse_rss_feed, fetch_and_parse_article
from services.tagger import extract_tags_nltk_yake

load_dotenv()

def process_feed(ch, method, properties, body):
    """
    Callback function to process messages from the RSS queue.
    """
    print(" [x] Received a new RSS feed to process...")
    
    try:
        message = json.loads(body)
        feed_url = message.get('feed_url')
        raw_content = message.get('raw_content')

        if not feed_url or not raw_content:
            print(" [!] Invalid message format. Missing 'feed_url' or 'raw_content'.")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return

        articles_from_feed = parse_rss_feed(raw_content)
        print(f" [ ] Found {len(articles_from_feed)} articles in feed: {feed_url}")

        mongo_collection = get_mongo_collection()

        for article_meta in articles_from_feed:
            article_url = article_meta['url']
            
            # 2. Check if we already have this article to avoid reprocessing
            if mongo_collection.count_documents({"url": article_url}, limit=1) > 0:
                print(f" [ ] Article already exists, skipping: {article_url}")
                continue

            full_article = fetch_and_parse_article(article_url)
            if not full_article:
                print(f" [!] Could not fetch or parse content for: {article_url}")
                continue
            
            tags = extract_tags_nltk_yake(full_article['content'])
            
            final_document = {
                "source_feed_url": feed_url,
                "title": full_article.get('title', article_meta.get('title')),
                "url": article_url,
                "byline": full_article.get('byline'),
                "content": full_article['content'],
                "tags": tags,
                "published_date": article_meta.get('published'),
                "scraped_at": datetime.datetime.now(datetime.timezone.utc)
            }

            mongo_collection.insert_one(final_document)
            print(f" [✓] Successfully processed and stored: {final_document['title']}")

    except json.JSONDecodeError:
        print(" [!] Failed to decode JSON from message body.")
    except Exception as e:
        print(f" [!] An error occurred during processing: {e}")
    finally:
        ch.basic_ack(delivery_tag=method.delivery_tag)
        print(" [x] Done processing message.\n")


def main():
    try:
        connection, channel = get_rabbitmq_connection_and_channel()
        queue_name = os.environ.get("RSS_QUEUE_NAME", "raw_content_queue")
        
        channel.queue_declare(queue=queue_name, durable=True)
        print(" [*] Waiting for messages. To exit press CTRL+C")

        channel.basic_qos(prefetch_count=1)
        
        channel.basic_consume(queue=queue_name, on_message_callback=process_feed)
        channel.start_consuming()

    except KeyboardInterrupt:
        print(" [!] Interrupted by user. Shutting down.")
        if 'channel' in locals() and channel.is_open:
            channel.close()
        if 'connection' in locals() and connection.is_open:
            connection.close()
    except Exception as e:
        print(f" [!] A critical error occurred: {e}")

if __name__ == '__main__':
    import datetime
    main()
