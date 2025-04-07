# Network-Analytics
A network analytics dashboard project  
# 🌍 IP Location Dashboard

A Python-based dashboard that utilizes the [GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database to display geographic information based on IP addresses.

## 🚀 Features

- IP geolocation lookup using MaxMind's GeoLite2 database
- Clean and extensible Python codebase
- Lightweight and easy to set up
- Can be extended into a web dashboard or analytics pipeline

## 🧰 Requirements

- Python 3.7+
- pip
- GeoLite2-City.mmdb file (from MaxMind)

## 📦 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/<your-username>/<repo-name>.git
   cd <repo-name>
Create a virtual environment (optional but recommended)

bash
Copy
Edit
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
Install dependencies

bash
Copy
Edit
pip install -r requirements.txt
Download the GeoLite2-City.mmdb

Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Place the .mmdb file in the root directory of this project.

📊 Usage
Run the dashboard script:

bash
Copy
Edit
python dashboard.py
You can extend or modify it to support:

Web-based frontends (e.g., Flask, Streamlit)

IP log ingestion from files or APIs

Real-time geolocation tracking

📁 Project Structure
Copy
Edit
.
├── dashboard.py
├── requirements.txt
├── .gitignore
└── README.md
⚖️ License
This project is licensed under the MIT License.

Note: The GeoLite2-City.mmdb file is not included due to MaxMind's license. Please download it separately.
