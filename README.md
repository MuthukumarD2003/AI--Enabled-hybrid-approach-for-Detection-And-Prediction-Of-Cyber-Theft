# 📧🔐 AI-Enabled Hybrid Spam Detection System

## Overview

This intelligent spam detection system uses a hybrid approach combining machine learning algorithms with traditional rule-based filtering to identify and prevent cyber threats in both SMS and email messages. The system helps protect users from phishing attempts, scams, and other social engineering attacks by analyzing message content and providing risk assessments.

## ✨ Key Features

- **Hybrid Detection**: Combines machine learning classification with keyword-based analysis
- **Multi-Platform Protection**: Works with both SMS texts and email content
- **Smart Analysis**: Detects suspicious patterns, urgency tactics, and questionable URLs
- **Risk Scoring**: Provides detailed risk assessment with threat breakdown
- **URL Analysis**: Examines links for potential phishing indicators
- **User Management**: Complete user authentication system with secure registration
- **History Tracking**: Maintains a record of all scanned messages for reference
- **Intuitive UI**: Clean, responsive web interface built with Bootstrap

## 🛠️ Technology Stack

- **Backend**: Python with Flask web framework
- **Machine Learning**: Custom-trained text classification model
- **Natural Language Processing**: NLTK for text tokenization and processing
- **Data Storage**: SQLite database for user accounts and scan history
- **Frontend**: HTML, CSS, Bootstrap 5 for responsive design
- **Security**: CSRF protection, password hashing, and secure session management

## 🚀 Getting Started

### Prerequisites

- Python 3.7+
- pip package manager

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ai-spam-detection.git
   cd ai-spam-detection
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Run the application:
   ```
   python app.py
   ```

5. Access the web interface at `http://localhost:5000`

## 📊 How It Works

1. **Text Analysis**: The system analyzes message content for suspicious patterns, including urgency language, requests for personal information, and promises of unrealistic rewards.

2. **URL Detection**: Any URLs within the message are extracted and analyzed for phishing indicators like suspicious TLDs, long domains, or misleading paths.

3. **Feature Extraction**: The system converts the message into numerical features including text length, word count, special character ratio, and presence of suspicious keywords.

4. **Risk Assessment**: A risk score (0-100) is calculated based on detected patterns and features, with a corresponding risk level (Low, Medium, or High).

5. **Recommendations**: The system provides specific recommendations based on the detected threats.

## 👤 User Interface

- **Login/Register**: Secure user authentication system
- **Dashboard**: Main interface for submitting content for scanning
- **Results**: Detailed breakdown of scan results with threat analysis
- **History**: Full history of previously scanned messages

## 🔒 Security Features

- Password hashing using SHA-256
- CSRF protection for all forms
- Secure session management
- Input validation and sanitization
- SQL injection prevention

## 🧠 Machine Learning Model

The system employs a custom-trained model that evaluates multiple message characteristics:
- Special character distribution
- Uppercase word ratio
- Urgency indicators
- Suspicious keyword frequency
- URL characteristics
- Content patterns associated with social engineering

## 📝 Future Enhancements

- Real-time email integration
- Browser extension for instant protection
- API endpoints for third-party integration
- Advanced ML model with regular retraining
- Two-factor authentication
- Additional language support

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
