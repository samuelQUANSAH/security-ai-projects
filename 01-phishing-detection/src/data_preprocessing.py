"""
Data preprocessing pipeline for Phishing Detection Engine.
Handles text cleaning, URL extraction, and dataset preparation.
"""

import re
import pandas as pd
from typing import List, Tuple
from urllib.parse import urlparse
import nltk
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords


# Download NLTK data on first import
# nltk.download('punkt')
# nltk.download('stopwords')


class TextPreprocessor:
    """Clean and normalize email text for BERT fine-tuning."""

    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
        self.url_pattern = re.compile(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        )

    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from text."""
        return self.url_pattern.findall(text)

    def clean_text(self, text: str, remove_urls: bool = True) -> str:
        """
        Normalize text for model input.
        - Lowercase
        - Remove special characters (keep sentence structure)
        - Optionally remove URLs (replaced with [URL] token)
        """
        if remove_urls:
            text = self.url_pattern.sub(' [URL] ', text)

        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)

        # Remove excessive punctuation but keep sentence delimiters
        text = re.sub(r'[^\w\s\.\?\!]', ' ', text)

        return text.strip().lower()

    def tokenize_for_bert(self, text: str, max_length: int = 512) -> str:
        """
        Prepare text for BERT tokenizer.
        BERT WordPiece handles subword tokenization — we just ensure clean input.
        """
        cleaned = self.clean_text(text)
        # Truncate to approximate word limit (BERT token limit is ~512 subword tokens)
        words = cleaned.split()
        if len(words) > 400:  # Conservative estimate: ~1.3 tokens/word
            words = words[:400]
        return ' '.join(words)


class URLFeatureExtractor:
    """Extract lexical and host-based features from URLs for RF classifier."""

    @staticmethod
    def extract_features(url: str) -> dict:
        """
        Extract 15+ URL features commonly used in phishing detection research.
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return URLFeatureExtractor._default_features()

        hostname = parsed.netloc
        path = parsed.path

        features = {
            'url_length': len(url),
            'hostname_length': len(hostname),
            'path_length': len(path),
            'n_dots': url.count('.'),
            'n_hyphens': url.count('-'),
            'n_at': url.count('@'),
            'n_question_marks': url.count('?'),
            'n_and': url.count('&'),
            'n_equal': url.count('='),
            'n_underscores': url.count('_'),
            'n_slashes': url.count('/'),
            'n_digits': sum(c.isdigit() for c in url),
            'has_ip_address': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', hostname))),
            'has_https': int(parsed.scheme == 'https'),
            'tld_length': len(hostname.split('.')[-1]) if '.' in hostname else 0,
            'n_subdomains': hostname.count('.') - 1 if '.' in hostname else 0,
            'has_suspicious_tld': int(
                hostname.split('.')[-1].lower() in {'tk', 'ml', 'ga', 'cf', 'top', 'xyz'}
                if '.' in hostname else False
            ),
            'has_shortening_service': int(
                any(svc in hostname for svc in {'bit.ly', 't.co', 'goo.gl', 'tinyurl'})
            ),
        }

        return features

    @staticmethod
    def _default_features() -> dict:
        """Return default feature vector for unparseable URLs."""
        return {k: 0 for k in [
            'url_length', 'hostname_length', 'path_length', 'n_dots',
            'n_hyphens', 'n_at', 'n_question_marks', 'n_and', 'n_equal',
            'n_underscores', 'n_slashes', 'n_digits', 'has_ip_address',
            'has_https', 'tld_length', 'n_subdomains', 'has_suspicious_tld',
            'has_shortening_service'
        ]}


class DatasetBuilder:
    """Load and prepare Enron + phishing datasets."""

    def __init__(self, data_dir: str = './data'):
        self.data_dir = data_dir
        self.text_processor = TextPreprocessor()
        self.url_extractor = URLFeatureExtractor()

    def load_raw(self) -> pd.DataFrame:
        """
        Placeholder: Load raw email data.
        In production: Load Enron + Phishing Corpus, merge, deduplicate.
        """
        # TODO: Implement actual data loading
        raise NotImplementedError("Implement data loading from Enron + phishing sources")

    def build_training_data(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """
        Build two datasets:
        1. Text dataset: [email_text, label] for BERT
        2. URL dataset: [url_features, label] for Random Forest
        """
        raw = self.load_raw()

        # Text dataset
        text_df = pd.DataFrame({
            'text': raw['body'].apply(self.text_processor.tokenize_for_bert),
            'label': raw['label']
        })

        # URL dataset — expand one row per URL per email
        url_rows = []
        for _, row in raw.iterrows():
            urls = self.text_processor.extract_urls(row['body'])
            for url in urls:
                features = self.url_extractor.extract_features(url)
                features['label'] = row['label']
                url_rows.append(features)

        url_df = pd.DataFrame(url_rows)

        return text_df, url_df


if __name__ == '__main__':
    # Quick test
    preprocessor = TextPreprocessor()
    sample = "Visit https://evil-site.com/login?user=admin to verify your account NOW!"
    print("Cleaned:", preprocessor.clean_text(sample))
    print("URLs:", preprocessor.extract_urls(sample))

    url_feats = URLFeatureExtractor.extract_features("https://evil-site.com/login?user=admin")
    print("Features:", url_feats)
