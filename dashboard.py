import streamlit as st
import pandas as pd
import threading
import time
import geoip2.database
import os
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
import logging
import pycountry
import plotly.express as px;

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Alert thresholds
PACKET_RATE_THRESHOLD = 50  # Packets per second
REPEATED_ACCESS_THRESHOLD = 30  # Packets from a single IP in a short time
UNUSUAL_PROTOCOLS = {'OTHER(99)', 'OTHER(100)'}  # Rare protocol numbers
BLOCKED_COUNTRIES = {'Russia', 'North Korea'}  # Example blocked countries

class PacketProcessor:
    """Process and analyze network packets with GeoIP mapping"""
    def __init__(self):
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        self.packet_data = []
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self.running = True
        self.alerts = []
        
        geoip_db_path = "GeoLite2-City.mmdb"
        self.geo_reader = geoip2.database.Reader(geoip_db_path) if os.path.exists(geoip_db_path) else None
        if not self.geo_reader:
            logger.warning("GeoIP database not found. IP mapping will be disabled.")

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
        if df.empty or 'timestamp' not in df.columns:
            logger.error("DataFrame is empty or missing 'timestamp' column.")
            return []

        alerts = []
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
        
        if not df_grouped.empty and df_grouped.max() > PACKET_RATE_THRESHOLD:
            alerts.append(f"High traffic volume detected: {df_grouped.max()} packets/s")
        
        unusual_protocols = df[df['protocol'].isin(UNUSUAL_PROTOCOLS)]
        if not unusual_protocols.empty:
            alerts.append(f"Unusual protocol detected: {unusual_protocols['protocol'].unique()}")
        
        frequent_ips = df['source'].value_counts()
        suspicious_ips = frequent_ips[frequent_ips > REPEATED_ACCESS_THRESHOLD]
        if not suspicious_ips.empty:
            alerts.append(f"Suspicious activity: {suspicious_ips.index.tolist()} accessing frequently")
        
        blocked_countries = df[df['country'].isin(BLOCKED_COUNTRIES)]
        if not blocked_countries.empty:
            alerts.append(f"Blocked country detected: {blocked_countries['country'].unique()}")
        
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
                    if len(self.packet_data) > 5000:
                        self.packet_data.pop(0)
        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def get_dataframe(self):
        with self.lock:
            df = pd.DataFrame(self.packet_data)
            if df.empty or 'timestamp' not in df.columns:
                logger.error("DataFrame is empty or missing 'timestamp'. Returning empty DataFrame.")
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
        return pycountry.countries.lookup(country_name).alpha_3  # Convert to ISO-3 country code
    except LookupError:
        return None


def create_visualizations(df):
    if df.empty:
        return
    if 'country' in df.columns:
        df_filtered = df[df['country'] != "Unknown"].copy()
        df_filtered['country_code'] = df_filtered['country'].apply(get_country_iso)
        df_filtered = df_filtered[df_filtered['country_code'].notnull()]
        
        logger.info(df[['source', 'country']].drop_duplicates())  # Log IP-country mapping
        if df['country'].nunique() == 1 and df['country'].iloc[0] == "Unknown":
            st.warning("No valid country data. GeoIP may not be working.")
    
    protocol_counts = df['protocol'].value_counts()
    st.plotly_chart(px.pie(values=protocol_counts.values, names=protocol_counts.index, title="Protocol Distribution"), use_container_width=True)
    
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
    st.plotly_chart(px.line(x=df_grouped.index, y=df_grouped.values, title="Packets per Second"), use_container_width=True)
    
    top_sources = df['source'].value_counts().head(10)
    st.plotly_chart(px.bar(x=top_sources.index, y=top_sources.values, title="Top Source IP Addresses"), use_container_width=True)
    
    if not df_filtered.empty:
        st.plotly_chart(px.scatter_geo(df_filtered, locations="country_code", hover_name="source", title="Geographical Distribution"), use_container_width=True)


def start_packet_capture():
    processor = PacketProcessor()
    def capture_packets():
        sniff(prn=processor.process_packet, store=False, stop_filter=lambda x: not processor.running)
    threading.Thread(target=capture_packets, daemon=True).start()
    return processor


def main():
    st.set_page_config(page_title="Network Traffic Analysis with Alerts", layout="wide")
    st.title("Real-time Network Traffic Analysis with Alerts")
    
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()
    processor = st.session_state.processor
    df = processor.get_dataframe()
    alerts = processor.get_alerts()
    
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        st.metric("Capture Duration", f"{time.time() - st.session_state.start_time:.2f}s")
    
    st.subheader("Alerts")
    if alerts:
        for alert in alerts:
            st.error(alert)
    else:
        st.success("No anomalies detected.")
    
    create_visualizations(df)
    
    st.subheader("Recent Packets")
    if not df.empty:
        st.dataframe(df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size', 'country', 'city']], use_container_width=True)
    
    if st.button('Refresh Data'):
        st.rerun()
    if st.button("Stop Capture"):
        processor.stop_capture()
        st.warning("Packet capturing stopped.")


if __name__ == "__main__":
    main()
