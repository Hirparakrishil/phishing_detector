
Phishing URL Detector
Overview
The Phishing URL Detector is a web application built with Flask that analyzes URLs to determine if they are legitimate or phishing attempts. It uses machine learning techniques to extract features from URLs and predict their safety.

Features
Analyze URLs to detect phishing attempts.
Provides detailed analysis results, including URL characteristics and security features.
User-friendly interface for easy interaction.
Technologies Used
Flask: A lightweight WSGI web application framework for Python.
Flask-CORS: A Flask extension for handling Cross-Origin Resource Sharing (CORS).
Pandas: A data manipulation and analysis library for Python.
Machine Learning: Custom model for detecting phishing URLs.
POST /analyze
Description: Analyzes a given URL to determine if it is phishing.
Request Body:
json
Run
Copy code
{
  "url": "http://example.com"
}
Response:
json
Run
Copy code
{
  "is_phishing": true,
  "confidence": 0.95,
  "details": {
    "url_analysis": {
      "length": 23,
      "has_ip_address": false,
      "has_suspicious_chars": true,
      "is_https": false
    },
    "domain_info": {
      "age": 5,
      "is_registered": true
    },
    "security": {
      "has_ssl": false,
      "ssl_valid": false
    },
    "content_analysis": {
      "has_suspicious_keywords": true,
      "form_count": 2,
      "external_links": 5
    }
  }
}
Error Handling
400 Bad Request: Returned if no URL is provided or if the URL format is invalid.
500 Internal Server Error: Returned for server errors during URL analysis.
