import streamlit as st
import pandas as pd
import threading
import time
import geoip2.database
import os
from datetime import datetime
from scapy.all import AsyncSniffer, IP, TCP, UDP
import logging
import pycountry
import plotly.express as px
from collections import deque
from fpdf import FPDF
import json

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Alert thresholds
PACKET_RATE_THRESHOLD = 50
REPEATED_ACCESS_THRESHOLD = 30
UNUSUAL_PROTOCOLS = {'OTHER(99)', 'OTHER(100)'}
BLOCKED_COUNTRIES = {'Russia', 'North Korea'}

class PacketProcessor:
    def __init__(self):
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        self.packet_data = deque(maxlen=5000)
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.running = True
        self.alerts = []

        try:
            geoip_db_path = "GeoLite2-City.mmdb"
            if os.path.exists(geoip_db_path):
                self.geo_reader = geoip2.database.Reader(geoip_db_path)
            else:
                self.geo_reader = None
                logger.warning("GeoIP database not found. IP mapping will be disabled.")
        except Exception as e:
            self.geo_reader = None
            logger.error(f"Failed to load GeoIP database: {e}")

    def get_protocol_name(self, protocol_num):
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def get_geo_location(self, ip_address):
        if not self.geo_reader:
            return "Unknown", "Unknown"
        try:
            location = self.geo_reader.city(ip_address)
            return location.country.name or "Unknown", location.city.name or "Unknown"
        except Exception:
            return "Unknown", "Unknown"

    def check_alerts(self, df):
        alerts = []
        if df.empty or 'timestamp' not in df.columns:
            logger.warning("DataFrame empty or missing 'timestamp'.")
            return alerts

        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('s')).size()

        if not df_grouped.empty and df_grouped.max() > PACKET_RATE_THRESHOLD:
            alerts.append(f"High traffic volume detected: {df_grouped.max()} packets/s")

        unusual_protocols = df[df['protocol'].isin(UNUSUAL_PROTOCOLS)]
        if not unusual_protocols.empty:
            alerts.append(f"Unusual protocol detected: {unusual_protocols['protocol'].unique()}")

        frequent_ips = df['source'].value_counts()
        suspicious_ips = frequent_ips[frequent_ips > REPEATED_ACCESS_THRESHOLD]
        if not suspicious_ips.empty:
            alerts.append(f"Suspicious IPs: {suspicious_ips.index.tolist()}")

        blocked_countries = df[df['country'].isin(BLOCKED_COUNTRIES)]
        if not blocked_countries.empty:
            alerts.append(f"Blocked country access: {blocked_countries['country'].unique()}")

        return alerts

    def process_packet(self, packet):
        try:
            if IP in packet:
                with self.lock:
                    country, city = self.get_geo_location(packet[IP].src)
                    packet_info = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'country': country,
                        'city': city
                    }
                    if TCP in packet:
                        packet_info.update({'src_port': packet[TCP].sport, 'dst_port': packet[TCP].dport})
                    elif UDP in packet:
                        packet_info.update({'src_port': packet[UDP].sport, 'dst_port': packet[UDP].dport})
                    self.packet_data.append(packet_info)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def get_dataframe(self):
        with self.lock:
            df = pd.DataFrame(self.packet_data)
            if df.empty or 'timestamp' not in df.columns:
                logger.warning("DataFrame is empty or missing 'timestamp'.")
                return pd.DataFrame()
            return df

    def get_alerts(self):
        df = self.get_dataframe()
        with self.lock:
            self.alerts = self.check_alerts(df)
            alerts = self.alerts[:]
            self.alerts.clear()
            return alerts

    def stop_capture(self):
        self.running = False

def get_country_iso(country_name):
    try:
        return pycountry.countries.lookup(country_name).alpha_3
    except LookupError:
        return None

def create_visualizations(df):
    if df.empty or 'timestamp' not in df.columns:
        st.warning("No valid data to display.")
        return

    if 'country' in df.columns:
        df_filtered = df[df['country'] != "Unknown"].copy()
        df_filtered['country_code'] = df_filtered['country'].apply(get_country_iso)
        df_filtered = df_filtered[df_filtered['country_code'].notnull()]

        logger.info(df[['source', 'country']].drop_duplicates())
        if df['country'].nunique() == 1 and df['country'].iloc[0] == "Unknown":
            st.warning("GeoIP mapping not working or not found.")

    protocol_counts = df['protocol'].value_counts()
    st.plotly_chart(px.pie(values=protocol_counts.values, names=protocol_counts.index, title="Protocol Distribution"), use_container_width=True)

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_grouped = df.groupby(df['timestamp'].dt.floor('s')).size()
    st.plotly_chart(px.line(x=df_grouped.index, y=df_grouped.values, title="Packets per Second"), use_container_width=True)

    top_sources = df['source'].value_counts().head(10)
    st.plotly_chart(px.bar(x=top_sources.index, y=top_sources.values, title="Top Source IPs"), use_container_width=True)

    if not df_filtered.empty:
        st.plotly_chart(px.scatter_geo(df_filtered, locations="country_code", hover_name="source", title="Geo Distribution"), use_container_width=True)

def generate_pdf_report(df, alerts):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Network Traffic Summary Report", ln=True, align='C')
    pdf.cell(200, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')

    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Top Alerts:", ln=True)
    pdf.set_font("Arial", size=11)
    for alert in alerts[:5]:
        pdf.cell(200, 10, txt=f"- {alert}", ln=True)

    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Top Source IPs:", ln=True)
    top_ips = df['source'].value_counts().head(5)
    pdf.set_font("Arial", size=11)
    for ip, count in top_ips.items():
        pdf.cell(200, 10, txt=f"{ip} - {count} packets", ln=True)

    return pdf.output(dest='S').encode('latin1')

def start_packet_capture():
    processor = PacketProcessor()
    sniffer = AsyncSniffer(prn=processor.process_packet, store=False)
    sniffer.start()
    processor.sniffer = sniffer
    return processor

def main():
    st.set_page_config(page_title="Network Traffic Analysis", layout="wide")
    st.title("📡 Real-time Network Traffic Analysis with Alerts")

    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()

    processor = st.session_state.processor
    df = processor.get_dataframe()
    alerts = processor.get_alerts()

    col1, col2 = st.columns(2)
    with col1:
        st.metric("📦 Total Packets", len(df))
    with col2:
        st.metric("⏱️ Duration", f"{time.time() - st.session_state.start_time:.2f}s")

    st.subheader("⚠️ Alerts")
    if alerts:
        for alert in alerts:
            st.error(alert)
    else:
        st.success("No anomalies detected.")

    create_visualizations(df)

    st.subheader("🧾 Recent Packets")
    if not df.empty:
        st.dataframe(df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size', 'country', 'city']], use_container_width=True)

        st.download_button(
            label="📤 Export as CSV",
            data=df.to_csv(index=False).encode('utf-8'),
            file_name=f'network_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv',
            mime='text/csv'
        )

        st.download_button(
            label="📤 Export as JSON",
            data=df.to_json(orient='records', date_format='iso').encode('utf-8'),
            file_name=f'network_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
            mime='application/json'
        )

        pdf_bytes = generate_pdf_report(df, alerts)
        st.download_button(
            label="📄 Export Summary PDF",
            data=pdf_bytes,
            file_name=f'network_summary_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf',
            mime='application/pdf'
        )

    col1, col2 = st.columns(2)
    with col1:
        if st.button('🔄 Refresh'):
            st.rerun()
    with col2:
        if st.button("🛑 Stop Capture"):
            processor.stop_capture()
            processor.sniffer.stop()
            st.warning("Packet capturing stopped.")

if __name__ == "__main__":
    main()
