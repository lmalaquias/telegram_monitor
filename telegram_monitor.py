#!/usr/bin/env python3
"""
Telegram Channel Monitor & Data Processor
Author: Leandro Malaquias
Purpose: For legitimate cybersecurity research and threat intelligence
"""

import asyncio
import os
import zipfile
import rarfile
import pandas as pd
from telethon import TelegramClient, events
from telethon.tl.types import MessageMediaDocument
import logging
from datetime import datetime
import json

class TelegramChannelMonitor:
    def __init__(self, api_id, api_hash, channel_username, excel_file):
        self.client = TelegramClient('session', api_id, api_hash)
        self.channel_username = channel_username
        self.excel_file = excel_file
        self.download_folder = 'downloads'
        self.processed_folder = 'processed'
        
        # Setup logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(__name__)
        
        # Create directories
        os.makedirs(self.download_folder, exist_ok=True)
        os.makedirs(self.processed_folder, exist_ok=True)
        
        # Initialize Excel file if not exists
        self.init_excel()
    
    async def test_connection(self):
        """Test connection and channel access"""
        try:
            print("Testing Telegram connection...")
            await self.client.start()
            print("✓ Connected to Telegram")
            
            # Test channel access
            channel = await self.client.get_entity(self.channel_username)
            print(f"✓ Found channel: {channel.title}")
            
            # Get recent messages count
            messages = await self.client.get_messages(channel, limit=5)
            print(f"✓ Can read messages (last 5 found)")
            
            print("Connection test successful!")
            return True
            
        except Exception as e:
            print(f"✗ Connection test failed: {e}")
            return False
    
    def init_excel(self):
        """Initialize Excel file with headers"""
        if not os.path.exists(self.excel_file):
            df = pd.DataFrame(columns=[
                'timestamp', 'filename', 'file_type', 'content_type', 
                'email', 'domain', 'password', 'additional_data', 'source_message_id'
            ])
            df.to_excel(self.excel_file, index=False)
    
    async def start_monitoring(self):
        """Start monitoring the Telegram channel"""
        try:
            print("Connecting to Telegram...")
            await self.client.start()
            print("Connected successfully!")
            
            self.logger.info(f"Started monitoring channel: {self.channel_username}")
            
            # Get channel entity with error handling
            try:
                channel = await self.client.get_entity(self.channel_username)
                print(f"Found channel: {channel.title}")
            except Exception as e:
                print(f"Error accessing channel {self.channel_username}: {e}")
                print("Make sure you're a member of the channel and it exists")
                return
            
            # Register event handler for new messages
            @self.client.on(events.NewMessage(chats=channel))
            async def handle_new_message(event):
                try:
                    await self.process_message(event.message)
                except Exception as e:
                    self.logger.error(f"Error handling message: {e}")
            
            print("Monitoring started. Press Ctrl+C to stop...")
            
            # Keep the client running
            await self.client.run_until_disconnected()
            
        except Exception as e:
            self.logger.error(f"Error in start_monitoring: {e}")
            raise
    
    async def process_message(self, message):
        """Process new messages from the channel"""
        try:
            if message.media and isinstance(message.media, MessageMediaDocument):
                document = message.media.document
                filename = None
                
                # Get filename from document attributes
                for attribute in document.attributes:
                    if hasattr(attribute, 'file_name'):
                        filename = attribute.file_name
                        break
                
                if filename and self.is_compressed_file(filename):
                    self.logger.info(f"Found compressed file: {filename}")
                    await self.download_and_process(message, filename)
                    
        except Exception as e:
            self.logger.error(f"Error processing message: {e}")
    
    def is_compressed_file(self, filename):
        """Check if file is compressed"""
        compressed_extensions = ['.zip', '.rar', '.7z', '.tar.gz', '.tar.bz2']
        return any(filename.lower().endswith(ext) for ext in compressed_extensions)
    
    async def download_and_process(self, message, filename):
        """Download and process compressed file"""
        try:
            # Download file
            download_path = os.path.join(self.download_folder, filename)
            await self.client.download_media(message, download_path)
            self.logger.info(f"Downloaded: {filename}")
            
            # Decompress and process
            extracted_content = self.decompress_file(download_path)
            
            # Process extracted content
            processed_data = self.process_extracted_content(extracted_content, message.id)
            
            # Add to Excel
            self.add_to_excel(processed_data)
            
            # Move processed file
            processed_path = os.path.join(self.processed_folder, filename)
            os.rename(download_path, processed_path)
            
            self.logger.info(f"Processed and moved: {filename}")
            
        except Exception as e:
            self.logger.error(f"Error downloading/processing {filename}: {e}")
    
    def decompress_file(self, file_path):
        """Decompress file and return content"""
        extracted_content = []
        
        try:
            if file_path.endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    for file_info in zip_ref.filelist:
                        if not file_info.is_dir():
                            with zip_ref.open(file_info) as f:
                                content = f.read().decode('utf-8', errors='ignore')
                                extracted_content.append({
                                    'filename': file_info.filename,
                                    'content': content
                                })
            
            elif file_path.endswith('.rar'):
                with rarfile.RarFile(file_path) as rar_ref:
                    for file_info in rar_ref.infolist():
                        if not file_info.is_dir():
                            content = rar_ref.read(file_info).decode('utf-8', errors='ignore')
                            extracted_content.append({
                                'filename': file_info.filename,
                                'content': content
                            })
                            
        except Exception as e:
            self.logger.error(f"Error decompressing {file_path}: {e}")
        
        return extracted_content
    
    def process_extracted_content(self, extracted_content, message_id):
        """Process extracted content and parse credentials"""
        processed_data = []
        
        for file_data in extracted_content:
            content = file_data['content']
            filename = file_data['filename']
            
            # Different parsing strategies based on file type
            if filename.endswith('.txt') or filename.endswith('.csv'):
                parsed_data = self.parse_credential_data(content, filename, message_id)
                processed_data.extend(parsed_data)
            
            elif filename.endswith('.json'):
                try:
                    json_data = json.loads(content)
                    parsed_data = self.parse_json_credentials(json_data, filename, message_id)
                    processed_data.extend(parsed_data)
                except:
                    pass
        
        return processed_data
    
    def parse_credential_data(self, content, filename, message_id):
        """Parse credential data from text content"""
        parsed_data = []
        
        lines = content.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Common credential formats
            # Format: email:password
            if ':' in line and '@' in line:
                parts = line.split(':', 1)
                if len(parts) == 2:
                    email = parts[0].strip()
                    password = parts[1].strip()
                    
                    if '@' in email:
                        domain = email.split('@')[1]
                        parsed_data.append({
                            'timestamp': datetime.now(),
                            'filename': filename,
                            'file_type': 'credentials',
                            'content_type': 'email:password',
                            'email': email,
                            'domain': domain,
                            'password': password,
                            'additional_data': '',
                            'source_message_id': message_id
                        })
            
            # Format: email;password;additional_info
            elif ';' in line and '@' in line:
                parts = line.split(';')
                if len(parts) >= 2:
                    email = parts[0].strip()
                    password = parts[1].strip()
                    additional = ';'.join(parts[2:]) if len(parts) > 2 else ''
                    
                    if '@' in email:
                        domain = email.split('@')[1]
                        parsed_data.append({
                            'timestamp': datetime.now(),
                            'filename': filename,
                            'file_type': 'credentials',
                            'content_type': 'email;password;info',
                            'email': email,
                            'domain': domain,
                            'password': password,
                            'additional_data': additional,
                            'source_message_id': message_id
                        })
        
        return parsed_data
    
    def parse_json_credentials(self, json_data, filename, message_id):
        """Parse credentials from JSON data"""
        parsed_data = []
        
        # Handle different JSON structures
        if isinstance(json_data, list):
            for item in json_data:
                if isinstance(item, dict) and 'email' in item:
                    email = item.get('email', '')
                    if '@' in email:
                        domain = email.split('@')[1]
                        parsed_data.append({
                            'timestamp': datetime.now(),
                            'filename': filename,
                            'file_type': 'credentials',
                            'content_type': 'json',
                            'email': email,
                            'domain': domain,
                            'password': item.get('password', ''),
                            'additional_data': json.dumps(item),
                            'source_message_id': message_id
                        })
        
        return parsed_data
    
    def add_to_excel(self, data):
        """Add processed data to Excel file"""
        if not data:
            return
        
        try:
            # Read existing data
            df_existing = pd.read_excel(self.excel_file)
            
            # Create new dataframe
            df_new = pd.DataFrame(data)
            
            # Combine and remove duplicates
            df_combined = pd.concat([df_existing, df_new], ignore_index=True)
            df_combined = df_combined.drop_duplicates(subset=['email', 'password'], keep='first')
            
            # Save back to Excel
            df_combined.to_excel(self.excel_file, index=False)
            
            self.logger.info(f"Added {len(data)} new records to Excel")
            
        except Exception as e:
            self.logger.error(f"Error adding to Excel: {e}")

# Configuration
CONFIG = {
    'api_id': YOUR_API_ID,
    'api_hash': 'YOUR_API_HASH',
    'channel_username': '@TARGET_CHANNEL',
    'excel_file': 'observer_credentials_data.xlsx'
}

async def main():
    try:
        print("Initializing Telegram Channel Monitor...")
        monitor = TelegramChannelMonitor(
            CONFIG['api_id'],
            CONFIG['api_hash'],
            CONFIG['channel_username'],
            CONFIG['excel_file']
        )
        
        # Test connection first
        if await monitor.test_connection():
            print("\nStarting monitoring...")
            await monitor.start_monitoring()
        else:
            print("Cannot start monitoring due to connection issues")
        
    except Exception as e:
        print(f"Error in main: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("Telegram Channel Monitor - For legitimate cybersecurity research only")
    print("Ensure you have proper authorization and legal compliance")
    
    # Install required packages:
    # pip install telethon pandas openpyxl rarfile
    
    # Windows asyncio
    import sys
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    except Exception as e:
        print(f"Critical error: {e}")
        import traceback
        traceback.print_exc()