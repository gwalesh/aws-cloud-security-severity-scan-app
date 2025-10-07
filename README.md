# Cloud Security Monitoring Application

A full-stack cloud security monitoring application that analyzes AWS resources for common security misconfigurations and provides AI-generated explanations and remediation steps.

## 🚀 Features

### Backend API (FastAPI)
- **Security Detection**: Identifies 5 common AWS security issues:
  - Public S3 buckets (without proper justification)
  - Old IAM access keys (>90 days)
  - Security groups with open ports (0.0.0.0/0)
  - Publicly accessible RDS instances
  - Unencrypted EC2 EBS volumes
- **Mock AI Generator**: Provides human-readable explanations and 3-step remediation plans
- **RESTful API**: Clean endpoints for scanning, listing, and retrieving findings
- **SQLite Database**: Persistent storage for findings with filtering and pagination
- **Comprehensive Testing**: Unit tests for all core functionality

### Frontend UI (Bootstrap)
- **Responsive Dashboard**: Real-time security metrics and resource breakdown
- **Interactive Findings Table**: Sortable, filterable table with pagination
- **Details Panel**: Slide-out panel with AI explanations and remediation steps
- **Dark Mode**: Toggle between light and dark themes
- **Modern UI**: Smooth animations, professional styling, and excellent UX
- **File Upload**: Easy JSON file upload for resource scanning

## 🏗️ Architecture

```
/
├── api/                    # Backend FastAPI application
│   ├── app/
│   │   ├── main.py        # FastAPI app and endpoints
│   │   ├── models.py      # Pydantic data models
│   │   ├── detector.py    # Security detection logic
│   │   ├── generator.py   # Mock AI explanation generator
│   │   └── database.py    # SQLite database setup
│   └── requirements.txt   # Python dependencies
├── web/                   # Frontend web application
│   ├── index.html         # Main HTML page
│   └── app.js            # JavaScript application logic
├── tests/                 # Unit tests
│   ├── test_detector.py  # Security detector tests
│   ├── test_generator.py # AI generator tests
│   └── test_api.py       # API endpoint tests
└── README.md             # This file
```

## 🛠️ Setup Instructions

### Prerequisites
- Python 3.8+
- Modern web browser
- Git

### Backend Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd cm_test
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   cd api
   pip install -r requirements.txt
   ```

4. **Run the API server**
   ```bash
   python -m app.main
   ```
   The API will be available at `http://localhost:8000`

5. **View API documentation**
   - Open `http://localhost:8000/docs` for interactive Swagger UI
   - Open `http://localhost:8000/redoc` for ReDoc documentation

### Frontend Setup

1. **Open the web application**
   - Simply open `web/index.html` in your web browser
   - Or serve it using a local web server:
     ```bash
     cd web
     python -m http.server 8080
     # Then open http://localhost:8080
     ```

### Running Tests

1. **Install test dependencies**
   ```bash
   pip install pytest
   ```

2. **Run all tests**
   ```bash
   cd tests
   python -m pytest -v
   ```

3. **Run specific test files**
   ```bash
   python -m pytest test_detector.py -v
   python -m pytest test_generator.py -v
   python -m pytest test_api.py -v
   ```

## 📊 Usage

### 1. Starting a Security Scan

1. Open the web application in your browser
2. Click the "New Scan" button
3. Upload a JSON file containing AWS resources
4. Click "Start Scan" to begin analysis

### 2. Sample JSON Format

```json
[
  {
    "type": "s3",
    "name": "my-bucket",
    "account_id": "123456789012",
    "properties": {
      "public": true,
      "tags": {
        "Environment": "prod"
      }
    }
  },
  {
    "type": "iam_user",
    "name": "john-doe",
    "account_id": "123456789012",
    "properties": {
      "access_key_age_days": 120
    }
  },
  {
    "type": "security_group",
    "name": "web-servers",
    "account_id": "123456789012",
    "properties": {
      "ingress_rules": [
        {
          "from_port": 22,
          "to_port": 22,
          "cidr_blocks": ["0.0.0.0/0"]
        }
      ]
    }
  }
]
```

### 3. Viewing Results

- **Dashboard**: Overview of findings by severity and resource type
- **Findings Table**: Detailed list with filtering and sorting
- **Details Panel**: Click any finding to see AI explanation and remediation steps

## 🔧 Technical Decisions

### Backend Technology Choices

- **FastAPI**: Modern, fast web framework with automatic API documentation
- **Pydantic**: Type-safe data validation and serialization
- **SQLAlchemy**: Robust ORM for database operations
- **SQLite**: Lightweight database perfect for this use case

### Frontend Technology Choices

- **Vanilla JavaScript**: No framework dependencies for simplicity
- **Bootstrap 5**: Modern, responsive CSS framework
- **Font Awesome**: Professional icon library
- **CSS Grid/Flexbox**: Modern layout techniques

### Security Detection Logic

- **Rule-based Detection**: Deterministic rules for consistent results
- **Configurable Thresholds**: Easy to adjust detection criteria
- **Evidence Collection**: Detailed evidence for each finding
- **Severity Classification**: Risk-based severity levels

### Mock AI Implementation

- **Template-based Generation**: Consistent, professional explanations
- **Resource-specific Content**: Tailored explanations for each resource
- **Structured Remediation**: Clear, actionable 3-step plans
- **Extensible Design**: Easy to add new rules and explanations

## 🧪 Testing Strategy

- **Unit Tests**: Comprehensive coverage of core logic
- **API Tests**: End-to-end testing of all endpoints
- **Edge Cases**: Testing with malformed data and error conditions
- **Mock Data**: Realistic test scenarios with various resource types

## 🚀 Future Enhancements

- **Real AWS Integration**: Connect to actual AWS APIs
- **More Security Rules**: Expand detection capabilities
- **User Authentication**: Multi-user support with role-based access
- **Scheduled Scans**: Automated periodic scanning
- **Export Functionality**: PDF/CSV export of findings
- **Real AI Integration**: Connect to actual AI services for explanations

## 📝 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan` | Start security scan with resource data |
| GET | `/findings` | List findings with optional filters |
| GET | `/findings/{id}` | Get detailed information for a specific finding |
| GET | `/findings/summary/stats` | Get summary statistics |
| GET | `/health` | Health check endpoint |

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For questions or issues, please open a GitHub issue or contact the development team.

---

**Note**: This application is designed for demonstration purposes and uses mock AI generation. In a production environment, you would integrate with actual AI services and AWS APIs for real-time security monitoring.

🎯 Ready to Use
The application is now complete and ready for demonstration. You can:
Start the backend: cd api && python -m app.main
Open the frontend: Open web/index.html in your browser
Upload sample data: Use the provided sample_data.json file
Run tests: cd tests && python -m pytest -v
