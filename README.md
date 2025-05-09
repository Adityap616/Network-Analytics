# Network-Analytics
A network analytics dashboard project  

# 🌍 IP Location Dashboard

A Python-based dashboard that utilizes the [GeoLite2-City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database to display geographic information based on IP addresses.

## 🚀 Features

- IP geolocation lookup using MaxMind's GeoLite2 database
- Real-time network traffic analysis and alerting system
- Monitor and visualize packet information such as source/destination IPs, protocols, and data size
- Identifies and alerts on:
  - High traffic volume
  - Unusual protocols
  - Repeated access from suspicious IPs
  - Access from blocked countries
- Geo-location visualization on a world map
- Export packet data to CSV, JSON, or PDF format
- Web-based interface using Streamlit for ease of use
- Clean and extensible Python codebase
- Lightweight and easy to set up
- Can be extended into a web dashboard or analytics pipeline

## 🧰 Requirements

- Python 3.7+
- pip
- GeoLite2-City.mmdb file (from MaxMind)
- Additional dependencies (listed in `requirements.txt`)

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
Features in Action:
Real-Time Network Monitoring: The dashboard continuously captures network traffic and provides insights on packet flow, protocol types, and data size.

Alerts and Notifications: Get notified about high traffic volume, unusual protocols, suspicious IP access, and blocked countries.

Geolocation Mapping: Visualize the source of network traffic using GeoIP mapping, showing the locations of IP addresses on a world map.

Export Data: Export captured network traffic data to CSV, JSON, or PDF formats for further analysis or reporting.

Extend or Modify:
Web-based Frontends: Extend the dashboard to web-based platforms such as Flask or Streamlit.

IP Log Ingestion: Integrate the system with external log files or APIs for enhanced data processing.

Real-time Geolocation Tracking: Implement real-time tracking of network activity with geolocation data.

📁 Project Structure
bash
Copy
Edit
.
├── dashboard.py          # Main application script
├── requirements.txt      # List of dependencies
├── .gitignore            # Git ignore file
├── README.md             # Project documentation
⚖️ License
This project is licensed under the MIT License.

Note: The GeoLite2-City.mmdb file is not included due to MaxMind's license. Please download it separately.

sql
Copy
Edit

### Key Additions:
1. **Real-Time Traffic Analysis and Alerts**: Describes the real-time network analysis, alerting on high traffic, unusual protocols, suspicious IPs, and blocked countries.
2. **Geo-location Visualization**: Mentions the ability to visualize network traffic geographically using the GeoLite2 database.
3. **Data Exporting**: Highlights the export options to CSV, JSON, and PDF formats.
4. **Usage Section**: Updates to include the real-time traffic monitoring features and their configuration. 

Feel free to modify any parts as per your project’s needs!
