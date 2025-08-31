# 📡 Telegram Channel Monitor

**Author: Leandro Malaquias**

An automated Python tool for monitoring Telegram channels, downloading compressed files, extracting credential data, and organizing it into Excel spreadsheets for cybersecurity threat intelligence and defensive research purposes.

## 🎯 Purpose

This tool is designed for **legitimate cybersecurity professionals** and **threat intelligence researchers** to:

- Monitor threat intelligence channels for new data dumps
- Automatically process compressed credential files  
- Extract and organize breach data for defensive purposes
- Track compromised credentials for client protection
- Build comprehensive threat intelligence databases

## ✨ Features

### 🔄 **Automated Monitoring**
- Real-time monitoring of Telegram channels
- Automatic detection of compressed files (ZIP, RAR, 7z, TAR)
- Background processing with minimal user intervention

### 📁 **Smart File Processing**  
- Downloads and decompresses files automatically
- Supports multiple archive formats (ZIP, RAR, 7z, etc.)
- Parses various credential formats:
  - `email:password`
  - `email;password;additional_info`
  - JSON structured data
  - Custom text formats

### 📊 **Data Management**
- Exports to Excel with organized columns
- Automatic deduplication to prevent duplicates
- Timestamping and source tracking
- File organization (downloads/processed folders)

### 🛡️ **Security Features**
- Session management for continuous monitoring
- Error handling and logging
- Secure credential storage
- Data validation and sanitization

## 🚀 Installation

### Prerequisites
- Python 3.7+
- Telegram API credentials (api_id and api_hash)
- Access to target Telegram channel

### Install Dependencies
```bash
pip install telethon pandas openpyxl rarfile
```

### Get Telegram API Credentials
1. Go to [https://my.telegram.org](https://my.telegram.org)
2. Log in with your phone number
3. Go to "API Development Tools"
4. Create a new application
5. Copy your `api_id` and `api_hash`

## ⚙️ Configuration

Edit the configuration section in the script:

```python
CONFIG = {
    'api_id': YOUR_API_ID,
    'api_hash': 'YOUR_API_HASH', 
    'channel_username': '@TARGET_CHANNEL',
    'excel_file': 'threat_intelligence_data.xlsx'
}
```

## 📖 Usage

### Basic Usage
```bash
python telegram_monitor.py
```

### First Run Setup
1. Script will request your phone number (with country code: `+1234567890`)
2. Enter the verification code sent via SMS
3. If 2FA is enabled, enter your Telegram password
4. Monitor will start automatically

## 📊 Output Format

The tool generates an Excel file with the following columns:

| Column | Description |
|--------|-------------|
| `timestamp` | When the data was processed |
| `filename` | Original compressed file name |
| `file_type` | Type of data found |
| `content_type` | Format of the credentials |
| `email` | Extracted email address |
| `domain` | Domain from email |
| `password` | Associated password |
| `additional_data` | Extra information found |
| `source_message_id` | Telegram message reference |

## 🔧 Supported File Formats

### Archive Formats
- ZIP files (`.zip`)
- RAR files (`.rar`)
- 7-Zip files (`.7z`)
- TAR files (`.tar.gz`, `.tar.bz2`)

### Data Formats
- **Plain Text**: `email:password` format
- **CSV**: `email;password;info` format  
- **JSON**: Structured credential objects
- **Custom**: Configurable parsing patterns

## 🔐 Security Considerations

### Operational Security
- Run in isolated environments (VMs recommended)
- Use VPN for additional privacy
- Regularly rotate API credentials
- Secure storage of output data

## ⚖️ Legal Disclaimer

**IMPORTANT**: This tool is intended exclusively for:

- ✅ **Legitimate cybersecurity research**
- ✅ **Defensive threat intelligence**
- ✅ **Authorized security assessments**
- ✅ **Educational purposes**

**Prohibited Uses:**
- ❌ Unauthorized access to private data
- ❌ Malicious activities or attacks
- ❌ Violation of platform terms of service
- ❌ Distribution of stolen credentials

Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse of this software.

## 📄 License

This project is licensed under the GNU License
