from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import pandas as pd
from phishing_detector import PhishingDetector, main

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Initialize and train the detector
detector = PhishingDetector()

# Training data
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

# Create training dataset
urls = legitimate_urls + phishing_urls
labels = [0] * len(legitimate_urls) + [1] * len(phishing_urls)

# Extract features and train
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

# Train the model
detector.train(X, y)

# Get the absolute path to the directory containing app.py
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def serve_frontend():
    return send_from_directory(BASE_DIR, 'index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    try:
        data = request.get_json()
        url = data.get('url')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'Invalid URL format. URL must start with http:// or https://'}), 400
            
        # Analyze the URL using your detector
        try:
            result = detector.predict(url)
            
            # Format the response
            response = {
                'is_phishing': result['is_phishing'],
                'confidence': result['confidence'],
                'details': {
                    'url_analysis': {
                        'length': result['features']['url_length'],
                        'has_ip_address': result['features']['has_ip_address'],
                        'has_suspicious_chars': result['features']['has_suspicious_chars'],
                        'is_https': result['features']['is_https']
                    },
                    'domain_info': {
                        'age': result['features']['domain_age'],
                        'is_registered': result['features']['is_registered']
                    },
                    'security': {
                        'has_ssl': result['features']['has_ssl'],
                        'ssl_valid': result['features']['ssl_valid']
                    },
                    'content_analysis': {
                        'has_suspicious_keywords': result['features']['has_suspicious_keywords'],
                        'form_count': result['features']['form_count'],
                        'external_links': result['features']['external_links']
                    }
                }
            }
            
            return jsonify(response)
        except Exception as analysis_error:
            print(f"Analysis error: {str(analysis_error)}")
            return jsonify({'error': 'Error during URL analysis. The URL might be inaccessible or invalid.'}), 400
    
    except Exception as e:
        print(f"Error analyzing URL: {str(e)}")  # Log the error
        return jsonify({'error': 'Server error. Please try again.'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)