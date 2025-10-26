import yake
import requests
from readabilipy import simple_json_from_html_string

headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'}
req = requests.get('https://en.wikipedia.org/wiki/Readability'.strip(), headers=headers, timeout=10)
article = simple_json_from_html_string(req.text, use_readability=True)

def extract_tags_nltk_yake(text, max_tags=10):
    """
    Extracts keywords from text using the YAKE! algorithm.
    YAKE! is great because it's language-independent and doesn't need a model.
    """
    kw_extractor = yake.KeywordExtractor(
        lan="en",          # Language
        n=3,               # Max n-gram size (e.g., up to 3-word phrases)
        dedupLim=0.8,      # Deduplication threshold (lower = more deduplication)
        top=max_tags,      # Number of keywords to return
        features=None
    )
    
    keywords = kw_extractor.extract_keywords(text)
    
    # Lower score is better in YAKE!
    print(keywords)
    return [kw for kw, score in keywords]

# if __name__ == '__main__':
#     article_text = """
#     In this tutorial, we'll explore advanced React Hooks. We will build a custom hook
#     for managing websockets in a React application. Understanding React Hooks is 
#     essential for modern React development. This goes beyond basic state management 
#     and introduces new patterns for handling side effects in function components.
#     """
    
#     tags = extract_tags_nltk_yake(article_text)
#     print(tags)
#     print(article)


