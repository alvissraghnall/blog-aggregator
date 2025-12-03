import requests
import feedparser
from readabilipy import simple_json_from_html_string
from bs4 import BeautifulSoup

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'
}

def parse_rss_feed(raw_xml_content):
    """
    Parses raw RSS XML content and returns a list of articles.
    """
    feed = feedparser.parse(raw_xml_content)
    articles = []
    for entry in feed.entries:
        if hasattr(entry, 'link'):
            articles.append({
                "title": entry.title,
                "url": entry.link,
                "published": entry.get("published")
            })
    return articles

def fetch_and_parse_article(url):
    """
    Fetches the full HTML content of an article URL and extracts the clean text.
    Implements a fallback strategy for content extraction.
    """
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()

        article = simple_json_from_html_string(response.text, use_readability=True)
        clean_content = None

        if article and article.get('plain_text'):
            plain_text_list = article['plain_text']
            valid_text_parts = [part for part in plain_text_list if isinstance(part, str)]
            
            if valid_text_parts:
                clean_content = " ".join(valid_text_parts)

        if not clean_content and article and article.get('plain_content'):
            print(f" [!] Primary extraction failed for {url}. Trying fallback with 'plain_content'.")

            soup = BeautifulSoup(article['plain_content'], "html.parser")
            clean_content = soup.get_text(separator=' ', strip=True)

        if not clean_content:
            print(f" [!] Both extraction methods failed for URL: {url}. Skipping.")
            return None

        return {
            "title": article.get('title'),
            "byline": article.get('byline'),
            "content": clean_content,
            "url": url
        }

    except requests.RequestException as e:
        print(f"Error fetching article {url}: {e}")
        return None
