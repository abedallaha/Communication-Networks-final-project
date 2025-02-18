# Network Traffic Analysis Project

This project analyzes network traffic patterns from PCAP files to identify and characterize different types of network applications (web browsing, video conferencing, and streaming).

## Features

- Extracts and analyzes packet data from PCAP files
- Generates visualizations of traffic patterns
- Identifies application types based on traffic characteristics
- Provides detailed analysis of security and privacy implications

## Requirements

- Python 3.x
- Required Python packages:
  - pyshark
  - pandas
  - matplotlib
  - seaborn

## Installation

1. Clone this repository:
```bash
git clone [your-repo-url]
cd [repo-name]
```

2. Install required packages:
```bash
pip install pyshark pandas matplotlib seaborn
```

## Usage

1. Place your PCAP files in the project root directory
2. Run the analysis script:
```bash
python src/network-traffic.py
```

The script will:
- Analyze all PCAP files in the current directory
- Generate visualizations in the `res` directory
- Create detailed analysis reports

## Project Structure

- `/src/` - Contains the source code
  - `network-traffic.py` - Main analysis script
- `/res/` - Contains analysis results
  - Visualizations (PNG files)
  - Analysis reports (CSV and TXT files)

## Results

The analysis generates several outputs:
1. Packet size distribution
2. Traffic patterns over time
3. Protocol distribution
4. Transport layer analysis
5. Detailed application pattern analysis
6. Security and privacy implications report

## Research Papers Summary

This project builds upon the findings of three key research papers in network traffic analysis:

### 1. FlowPic: Encrypted Internet Traffic Classification
- **Main Contribution**: Transforms network traffic into images for classification using CNNs
- **Key Features**: Analyzes packet size distributions, inter-packet timing, and flow volume
- **Results**: Achieves 99.7% accuracy in application identification, 98.4% for VPN traffic
- **Impact on Our Work**: Demonstrates that encrypted traffic maintains distinct, classifiable patterns

### 2. Early Traffic Classification Using TLS Encrypted ClientHello
- **Main Contribution**: Classifies traffic using TLS handshake metadata
- **Key Features**: Analyzes ClientHello parameters, packet sizes, and timing patterns
- **Results**: 94.6% accuracy in early traffic identification
- **Impact on Our Work**: Shows how metadata can reveal application types even before full data exchange

### 3. Identifying OS, Browser, and Application from HTTPS Traffic
- **Main Contribution**: Identifies system and application details from encrypted traffic
- **Key Features**: Uses TLS metadata, TCP window sizes, and packet burst patterns
- **Results**: 96.06% accuracy in OS, browser, and application identification
- **Impact on Our Work**: Confirms that transport-layer characteristics reveal application signatures

### Research Influence on Project
These papers guided our approach to:
- Pattern recognition in encrypted traffic
- Feature selection for traffic analysis
- Privacy implications of metadata exposure
- Application fingerprinting techniques

## Contributors

- 212810808 עבדאללה חמודה
- 214252538 דוחא גבאלי
- 325967610 סמר אטרש
- 213853039 האדיה אבו פנה

## Acknowledgments

This project uses the following tools and libraries:
- Wireshark/pyshark for packet capture analysis
- Pandas for data processing
- Matplotlib and Seaborn for visualization

## Note

Large PCAP files are not included in this repository due to size limitations. Sample PCAP files can be found at https://drive.google.com/drive/folders/1VF-oIj2k4emv6tkGx3yt7f2Pfxh7qfCN?usp=sharing. 