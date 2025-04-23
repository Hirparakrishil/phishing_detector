import requests
import re
import ssl
import socket
import whois
from datetime import datetime
from urllib.parse import urlparse
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

class PhishingDetector:
    def __init__(self):
        """Initialize the PhishingDetector with a Random Forest classifier"""
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.blacklists = self._load_blacklists()
        
    def _load_blacklists(self):
        """Load known phishing blacklists"""
        # Placeholder for blacklist loading
        return set()
        
    def extract_features(self, url):
        """Extract features from URL for phishing detection"""
        features = {}
        
        # 1. URL Structure Analysis
        parsed_url = urlparse(url)
        features['url_length'] = len(url)
        features['has_ip_address'] = self._has_ip_address(url)
        features['has_suspicious_chars'] = self._has_suspicious_chars(url)
        features['subdomain_count'] = len(parsed_url.netloc.split('.')) - 1
        features['is_https'] = parsed_url.scheme == 'https'
        
        # 2. Domain Analysis
        domain_info = self._analyze_domain(parsed_url.netloc)
        features.update(domain_info)
        
        # 3. SSL Certificate Analysis
        ssl_info = self._check_ssl(url)
        features.update(ssl_info)
        
        # 4. Content Analysis
        content_info = self._analyze_content(url)
        features.update(content_info)
        
        return features
    
    def _has_ip_address(self, url):
        """Check if URL contains IP address"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.search(ip_pattern, url))
    
    def _has_suspicious_chars(self, url):
        """Check for suspicious characters in URL"""
        suspicious_chars = ['@', '//', '--', '..', '&&']
        return any(char in url for char in suspicious_chars)
    
    def _analyze_domain(self, domain):
        """Analyze domain registration information"""
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            domain_age = (datetime.now() - creation_date).days if creation_date else 0
            
            return {
                'domain_age': domain_age,
                'is_registered': bool(domain_info.domain_name),
                'has_whois_privacy': 'privacy' in str(domain_info).lower()
            }
        except:
            return {
                'domain_age': 0,
                'is_registered': False,
                'has_whois_privacy': False
            }
    
    def _check_ssl(self, url):
        """Analyze SSL certificate information"""
        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'has_ssl': True,
                        'ssl_valid': True,
                        'cert_age': (datetime.now() - datetime.strptime(cert['notAfter'], 
                                   '%b %d %H:%M:%S %Y %Z')).days
                    }
        except:
            return {
                'has_ssl': False,
                'ssl_valid': False,
                'cert_age': 0
            }
    
    def _analyze_content(self, url):
        """Analyze website content for suspicious patterns"""
        try:
            response = requests.get(url, timeout=5)
            content = response.text.lower()
            
            suspicious_keywords = [
                'verify account', 'confirm identity', 'login details',
                'security check', 'limited time', 'act now'
            ]
            
            return {
                'has_suspicious_keywords': any(keyword in content for keyword in suspicious_keywords),
                'form_count': content.count('<form'),
                'external_links': len(re.findall(r'href=[\'"]?([^\'" >]+)', content))
            }
        except:
            return {
                'has_suspicious_keywords': False,
                'form_count': 0,
                'external_links': 0
            }
    
    def train(self, X, y):
        """Train the phishing detection model"""
        self.model.fit(X, y)
    
    def predict(self, url):
        """Predict if a URL is phishing or legitimate"""
        # Extract features
        features = self.extract_features(url)
        feature_df = pd.DataFrame([features])
        
        # Get model prediction
        prediction = self.model.predict(feature_df)[0]
        probability = self.model.predict_proba(feature_df)[0]
        
        return {
            'is_phishing': bool(prediction),
            'confidence': float(max(probability)),
            'features': features
        }

def main():
    """Main function to demonstrate the PhishingDetector"""
    # Initialize detector
    detector = PhishingDetector()
    
    # Expanded dataset with more examples
    legitimate_urls = [
        "https://www.google.com",
        "https://www.amazon.com",
        "https://www.microsoft.com",
        "https://www.facebook.com",
        "https://www.apple.com",
        "https://www.github.com",
        "https://www.linkedin.com",
        "https://www.twitter.com"
    ]
    
    phishing_urls = [
        "http://googgle.com.phishing.com",
        "http://192.168.1.1@malicious.com",
        "http://amaz0n.secure-login.com",
        "http://verify-account.com-secure.net",
        "http://banking-secure.com.verify.info",
        "http://login.account-update.com",
        "http://security-check.net-verify.com",
        "http://confirm-identity.secure-site.com"
    ]
    
    # Create balanced training dataset
    urls = legitimate_urls + phishing_urls
    labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)
    
    # Extract features
    features = []
    for url in urls:
        try:
            features.append(detector.extract_features(url))
        except Exception as e:
            print(f"Error extracting features for {url}: {str(e)}")
            continue
    
    X = pd.DataFrame(features)
    y = pd.Series(labels)
    
    # Handle missing values
    X = X.fillna(0)
    
    # Train model with stratified split to maintain class balance
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Train model
    detector.train(X_train, y_train)
    
    # Test the model
    y_pred = detector.model.predict(X_test)
    print("Model Accuracy:", accuracy_score(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    
    # Example prediction with known legitimate site
    test_url = "https://example.com"
    result = detector.predict(test_url)
    print(f"\nPrediction for {test_url}:")
    print(f"Is Phishing: {'Yes' if result['is_phishing'] else 'No'}")
    print(f"Confidence: {result['confidence']:.2f}")
    print("\nFeature values:")
    for feature, value in result['features'].items():
        print(f"{feature}: {value}")

if __name__ == "__main__":
    main()