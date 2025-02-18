import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
import os
import sys
from pathlib import Path

# Set up paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
RES_DIR = PROJECT_ROOT / "res"

def ensure_directory_exists(directory):
    """Ensure the specified directory exists, create if it doesn't"""
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        print(f"Error creating directory {directory}: {e}")
        sys.exit(1)

def extract_traffic_data(pcap_file):
    """Extract relevant network traffic data from PCAP file"""
    try:
        cap = pyshark.FileCapture(pcap_file)
        data = []
        
        for pkt in cap:
            try:
                timestamp = float(pkt.sniff_time.timestamp())
                protocol = pkt.highest_layer
                packet_length = int(pkt.length)
                src_ip = pkt.ip.src if hasattr(pkt, 'ip') else 'N/A'
                dst_ip = pkt.ip.dst if hasattr(pkt, 'ip') else 'N/A'
                
                # Handle transport layer information more carefully
                if hasattr(pkt, 'tcp'):
                    transport_layer = 'TCP'
                    src_port = pkt.tcp.srcport
                    dst_port = pkt.tcp.dstport
                elif hasattr(pkt, 'udp'):
                    transport_layer = 'UDP'
                    src_port = pkt.udp.srcport
                    dst_port = pkt.udp.dstport
                else:
                    transport_layer = 'N/A'
                    src_port = 'N/A'
                    dst_port = 'N/A'
                
                data.append([timestamp, protocol, packet_length, src_ip, dst_ip, transport_layer, src_port, dst_port])
            except AttributeError:
                continue
            except Exception as e:
                print(f"Warning: Error processing packet: {e}")
                continue
        
        cap.close()
        
        if not data:
            raise ValueError("No valid packets found in the PCAP file")
        
        return pd.DataFrame(data, columns=["Timestamp", "Protocol", "Packet Length", 
                                         "Source IP", "Destination IP", "Transport Layer",
                                         "Source Port", "Destination Port"])
    except Exception as e:
        print(f"Error processing PCAP file {pcap_file}: {e}")
        return pd.DataFrame()  # Return empty DataFrame on error

def analyze_protocols(df):
    protocol_counts = df['Protocol'].value_counts()
    transport_counts = df['Transport Layer'].value_counts()
    
    # Calculate average packet sizes per protocol
    protocol_sizes = df.groupby('Protocol')['Packet Length'].agg(['mean', 'std', 'count'])
    return protocol_counts, transport_counts, protocol_sizes

# Function to generate traffic analysis plots
def generate_plots(df, output_folder):
    os.makedirs(output_folder, exist_ok=True)
    
    # 1. Packet Size Distribution
    plt.figure(figsize=(12, 6))
    sns.histplot(data=df, x='Packet Length', bins=50, kde=True)
    plt.xlabel("Packet Length (Bytes)")
    plt.ylabel("Frequency")
    plt.title("Packet Size Distribution")
    plt.savefig(f"{output_folder}/packet_size_distribution.png")
    plt.close()
    
    # 2. Packet Count Over Time
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], unit='s')
    time_series = df.set_index('Timestamp').resample('1S').size()
    
    plt.figure(figsize=(12, 6))
    time_series.plot()
    plt.xlabel("Time")
    plt.ylabel("Packets per Second")
    plt.title("Network Traffic Over Time")
    plt.savefig(f"{output_folder}/traffic_over_time.png")
    plt.close()
    
    # 3. Protocol Distribution
    plt.figure(figsize=(12, 6))
    protocol_counts = df['Protocol'].value_counts()
    protocol_counts.plot(kind='bar')
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.title("Protocol Distribution")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f"{output_folder}/protocol_distribution.png")
    plt.close()
    
    # 4. Transport Layer Analysis
    plt.figure(figsize=(12, 6))
    transport_counts = df['Transport Layer'].value_counts()
    transport_counts.plot(kind='pie', autopct='%1.1f%%')
    plt.title("Transport Layer Distribution")
    plt.savefig(f"{output_folder}/transport_layer_distribution.png")
    plt.close()

def analyze_traffic_patterns(df):
    # Group traffic by source IP and analyze patterns
    ip_patterns = defaultdict(lambda: {'packet_counts': 0, 'avg_size': 0, 'protocols': set()})
    
    for _, row in df.iterrows():
        src_ip = row['Source IP']
        ip_patterns[src_ip]['packet_counts'] += 1
        ip_patterns[src_ip]['avg_size'] = ((ip_patterns[src_ip]['avg_size'] * 
                                           (ip_patterns[src_ip]['packet_counts'] - 1) +
                                           row['Packet Length']) / 
                                          ip_patterns[src_ip]['packet_counts'])
        ip_patterns[src_ip]['protocols'].add(row['Protocol'])
    
    return ip_patterns

def analyze_application_patterns(df):
    """Analyze patterns specific to different applications"""
    # Group data by application type based on port numbers and protocols
    app_patterns = {
        'Web Browsing': df[
            (df['Protocol'].isin(['TLS', 'TCP', 'HTTP', 'QUIC'])) &
            ((df['Destination Port'].isin(['443', '80', '8080'])) |
             (df['Source Port'].isin(['443', '80', '8080'])))
        ],
        'Video Conferencing': df[
            (df['Protocol'].isin(['DTLS', 'STUN', 'UDP'])) |
            ((df['Destination Port'].isin(['3478', '3479', '8801', '8802'])) |
             (df['Source Port'].isin(['3478', '3479', '8801', '8802'])))
        ],
        'Streaming': df[
            (df['Protocol'].isin(['QUIC', 'TLS'])) &
            ((df['Packet Length'] > 1000) |
             (df['Destination Port'].isin(['443'])))
        ]
    }
    
    analysis = {}
    for app_type, data in app_patterns.items():
        if not data.empty:
            # Convert timestamp to datetime if it's not already
            if not pd.api.types.is_datetime64_any_dtype(data['Timestamp']):
                data['Timestamp'] = pd.to_datetime(data['Timestamp'])
            
            # Calculate packets per minute
            packets_per_minute = len(data) / ((data['Timestamp'].max() - data['Timestamp'].min()).total_seconds() / 60)
            
            analysis[app_type] = {
                'packet_count': len(data),
                'avg_size': data['Packet Length'].mean(),
                'std_size': data['Packet Length'].std(),
                'protocols': data['Protocol'].value_counts().to_dict(),
                'packets_per_minute': packets_per_minute
            }
    
    return analysis

def generate_detailed_report(df, app_analysis, output_folder):
    """Generate a detailed analysis report"""
    report_path = f"{output_folder}/detailed_analysis_report.txt"
    
    with open(report_path, 'w') as f:
        f.write("Network Traffic Analysis Report\n")
        f.write("=============================\n\n")
        
        # 1. Overall Statistics
        f.write("1. Overall Traffic Statistics\n")
        f.write("----------------------------\n")
        f.write(f"Total Packets Analyzed: {len(df):,}\n")
        f.write(f"Total Data Transferred: {df['Packet Length'].sum() / (1024*1024):.2f} MB\n")
        f.write(f"Average Packet Size: {df['Packet Length'].mean():.2f} bytes\n")
        f.write(f"Time Period: {pd.to_datetime(df['Timestamp'].min()).strftime('%Y-%m-%d %H:%M:%S')} to {pd.to_datetime(df['Timestamp'].max()).strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # 2. Application Pattern Analysis
        f.write("2. Application Traffic Patterns\n")
        f.write("------------------------------\n")
        for app_type, stats in app_analysis.items():
            f.write(f"\n{app_type}:\n")
            f.write(f"- Packet Count: {stats['packet_count']:,}\n")
            f.write(f"- Average Packet Size: {stats['avg_size']:.2f} bytes\n")
            f.write(f"- Standard Deviation: {stats['std_size']:.2f} bytes\n")
            f.write("- Protocols Used: " + ", ".join(f"{k} ({v})" for k, v in stats['protocols'].items()) + "\n")
            f.write(f"- Packets per Minute: {stats['packets_per_minute']:.2f}\n")
        
        # 3. Traffic Pattern Analysis
        f.write("\n3. Traffic Pattern Analysis\n")
        f.write("-------------------------\n")
        f.write("Distinguishing Features by Application Type:\n\n")
        
        f.write("Web Browsing:\n")
        f.write("- Characterized by variable packet sizes\n")
        f.write("- Heavy use of TLS/HTTPS (port 443)\n")
        f.write("- Bursty traffic patterns\n")
        f.write("- Irregular intervals between packets\n")
        
        f.write("\nVideo Conferencing:\n")
        f.write("- Consistent, regular packet intervals\n")
        f.write("- High presence of UDP and DTLS\n")
        f.write("- STUN protocol for NAT traversal\n")
        f.write("- Bidirectional traffic with similar patterns\n")
        
        f.write("\nStreaming:\n")
        f.write("- Larger average packet sizes\n")
        f.write("- Sustained traffic patterns\n")
        f.write("- Heavy use of TCP and QUIC protocols\n")
        f.write("- More downstream than upstream traffic\n")
        
        # 4. Security Implications
        f.write("\n4. Security Implications\n")
        f.write("----------------------\n")
        f.write("Application Fingerprinting:\n")
        f.write("- Different applications show distinct traffic patterns\n")
        f.write("- Video conferencing can be identified by STUN/DTLS usage\n")
        f.write("- Streaming services show consistent large packet patterns\n")
        f.write("- Web browsing shows varied packet sizes and intervals\n\n")
        
        f.write("Privacy Considerations:\n")
        f.write("- Even with encryption, traffic patterns can reveal application usage\n")
        f.write("- Packet timing and size can indicate user activity\n")
        f.write("- Protocol usage can identify specific applications\n")
        f.write("- Regular patterns in video calls can reveal meeting duration\n")
        f.write("- Streaming patterns can indicate quality of content (HD vs SD)\n")

def main():
    try:
        # Ensure results directory exists
        ensure_directory_exists(RES_DIR)
        
        # Find PCAP files in project root
        pcap_files = list(PROJECT_ROOT.glob("*.pcap"))
        if not pcap_files:
            print("No PCAP files found in the project root directory!")
            return
        
        all_data = pd.DataFrame()
        
        for pcap_file in pcap_files:
            print(f"Analyzing {pcap_file.name}...")
            df = extract_traffic_data(pcap_file)
            if not df.empty:
                all_data = pd.concat([all_data, df])
        
        if all_data.empty:
            print("No valid data found in any PCAP files!")
            return
        
        # Save raw data
        all_data.to_csv(RES_DIR / "traffic_data.csv", index=False)
        
        # Generate visualizations
        generate_plots(all_data, RES_DIR)
        
        # Analyze protocols
        protocol_counts, transport_counts, protocol_sizes = analyze_protocols(all_data)
        protocol_analysis = pd.DataFrame({
            'Protocol_Counts': protocol_counts,
            'Transport_Counts': transport_counts
        })
        protocol_analysis.to_csv(RES_DIR / "protocol_analysis.csv")
        protocol_sizes.to_csv(RES_DIR / "protocol_sizes.csv")
        
        # Analyze traffic patterns
        traffic_patterns = analyze_traffic_patterns(all_data)
        
        # Analyze application patterns
        app_analysis = analyze_application_patterns(all_data)
        
        # Generate detailed report
        generate_detailed_report(all_data, app_analysis, RES_DIR)
        
        # Save traffic pattern analysis
        with open(RES_DIR / "traffic_patterns_analysis.txt", 'w') as f:
            f.write("Traffic Pattern Analysis\n")
            f.write("=======================\n\n")
            for ip, stats in traffic_patterns.items():
                f.write(f"Source IP: {ip}\n")
                f.write(f"Total Packets: {stats['packet_counts']}\n")
                f.write(f"Average Packet Size: {stats['avg_size']:.2f} bytes\n")
                f.write(f"Protocols Used: {', '.join(stats['protocols'])}\n")
                f.write("------------------------\n")
        
        print(f"Analysis completed. Results saved in {RES_DIR}/")
        
    except Exception as e:
        print(f"Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
