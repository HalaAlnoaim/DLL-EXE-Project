#!/usr/bin/env python3
"""
S-Rank Core - Configuration Manager
Handles all configuration loading and management for the project.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
from datetime import datetime

class ConfigManager:
    """Centralized configuration management for S-Rank Core."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Path to configuration directory. If None, uses default.
        """
        self.logger = logging.getLogger(__name__)
        
        # Determine config directory
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            # Default config directory relative to this file
            project_root = Path(__file__).parent.parent
            self.config_dir = project_root / "config"
            
        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)
        
        # Config file paths
        self.clients_config_path = self.config_dir / "clients.json"
        self.credentials_config_path = self.config_dir / "credentials.json"
        
        # Load configurations
        self._config_cache = {}
        self.reload_config()
        
    def reload_config(self):
        """Reload all configuration files."""
        self._config_cache.clear()
        self._load_clients_config()
        self._load_default_settings()
        
    def _load_clients_config(self):
        """Load clients configuration from JSON file."""
        if self.clients_config_path.exists():
            try:
                with open(self.clients_config_path, 'r', encoding='utf-8') as f:
                    self._config_cache['clients'] = json.load(f)
                self.logger.info(f"Loaded clients config from {self.clients_config_path}")
            except Exception as e:
                self.logger.error(f"Failed to load clients config: {e}")
                self._config_cache['clients'] = self._get_default_clients_config()
        else:
            self.logger.warning(f"Clients config not found at {self.clients_config_path}, using defaults")
            self._config_cache['clients'] = self._get_default_clients_config()
            self._save_default_clients_config()
            
    def _get_default_clients_config(self) -> Dict:
        """Get default clients configuration."""
        return {
            "clients": [
                {"id": "cipher", "name": "Cipher Security", "enabled": True, "priority": 1},
                {"id": "ksf", "name": "KSF Client", "enabled": True, "priority": 2},
                {"id": "osh", "name": "OSH Client", "enabled": True, "priority": 3},
                {"id": "jda", "name": "JDA Client", "enabled": True, "priority": 4},
                {"id": "fa", "name": "FA Client", "enabled": True, "priority": 5},
                {"id": "svc", "name": "SVC Client", "enabled": True, "priority": 6},
                {"id": "latis", "name": "Latis Client", "enabled": True, "priority": 7},
                {"id": "innova", "name": "Innova Client", "enabled": True, "priority": 8},
                {"id": "saip", "name": "SAIP Client", "enabled": True, "priority": 9},
                {"id": "golfsaudi", "name": "Golf Saudi", "enabled": True, "priority": 10}
            ],
            "api_settings": {
                "timeout": 30,
                "max_retries": 3,
                "per_page": 100,
                "base_url_template": "https://k{client}.ciphersa.net"
            },
            "processing_settings": {
                "technique_naming_format": "{technique}.{subtechnique}.{sub_subtechnique}",
                "include_disabled_rules": False,
                "excel_sheet_settings": {
                    "max_column_width": 100,
                    "wrap_text": True,
                    "auto_filter": True
                }
            }
        }
        
    def _save_default_clients_config(self):
        """Save default clients configuration to file."""
        try:
            with open(self.clients_config_path, 'w', encoding='utf-8') as f:
                json.dump(self._config_cache['clients'], f, indent=2, ensure_ascii=False)
            self.logger.info(f"Created default clients config at {self.clients_config_path}")
        except Exception as e:
            self.logger.error(f"Failed to save default clients config: {e}")
            
    def _load_default_settings(self):
        """Load default system settings."""
        self._config_cache['system'] = {
            "log_level": os.environ.get("SRANK_LOG_LEVEL", "INFO"),
            "debug_mode": os.environ.get("SRANK_DEBUG", "false").lower() == "true",
            "max_workers": int(os.environ.get("SRANK_MAX_WORKERS", "4")),
            "output_format": os.environ.get("SRANK_OUTPUT_FORMAT", "xlsx")
        }
        
    # === Client Management ===
    
    def get_clients(self, enabled_only: bool = True) -> List[Dict]:
        """
        Get list of clients.
        
        Args:
            enabled_only: Return only enabled clients
            
        Returns:
            List of client configurations
        """
        clients = self._config_cache.get('clients', {}).get('clients', [])
        
        if enabled_only:
            clients = [c for c in clients if c.get('enabled', True)]
            
        # Sort by priority
        return sorted(clients, key=lambda x: x.get('priority', 999))
        
    def get_client_ids(self, enabled_only: bool = True) -> List[str]:
        """Get list of client IDs."""
        clients = self.get_clients(enabled_only)
        return [client['id'] for client in clients]
        
    def get_client_config(self, client_id: str) -> Optional[Dict]:
        """Get configuration for a specific client."""
        clients = self.get_clients(enabled_only=False)
        for client in clients:
            if client['id'] == client_id:
                return client
        return None
        
    def add_client(self, client_id: str, name: str, enabled: bool = True, priority: Optional[int] = None) -> bool:
        """
        Add a new client to configuration.
        
        Args:
            client_id: Unique client identifier
            name: Client display name
            enabled: Whether client is enabled
            priority: Client priority (auto-assigned if None)
            
        Returns:
            True if client was added successfully
        """
        try:
            clients = self._config_cache.get('clients', {}).get('clients', [])
            
            # Check if client already exists
            if any(c['id'] == client_id for c in clients):
                self.logger.warning(f"Client {client_id} already exists")
                return False
                
            # Auto-assign priority if not provided
            if priority is None:
                max_priority = max([c.get('priority', 0) for c in clients], default=0)
                priority = max_priority + 1
                
            # Add new client
            new_client = {
                "id": client_id,
                "name": name,
                "enabled": enabled,
                "priority": priority
            }
            
            clients.append(new_client)
            self._config_cache['clients']['clients'] = clients
            
            # Save to file
            self._save_clients_config()
            
            self.logger.info(f"Added client: {client_id} ({name})")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add client {client_id}: {e}")
            return False
            
    def update_client(self, client_id: str, **updates) -> bool:
        """Update client configuration."""
        try:
            clients = self._config_cache.get('clients', {}).get('clients', [])
            
            for i, client in enumerate(clients):
                if client['id'] == client_id:
                    # Update fields
                    for key, value in updates.items():
                        if key in ['id', 'name', 'enabled', 'priority', 'description']:
                            client[key] = value
                    
                    clients[i] = client
                    self._config_cache['clients']['clients'] = clients
                    
                    # Save to file
                    self._save_clients_config()
                    
                    self.logger.info(f"Updated client: {client_id}")
                    return True
                    
            self.logger.warning(f"Client {client_id} not found")
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to update client {client_id}: {e}")
            return False
            
    def _save_clients_config(self):
        """Save clients configuration to file."""
        try:
            with open(self.clients_config_path, 'w', encoding='utf-8') as f:
                json.dump(self._config_cache['clients'], f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Failed to save clients config: {e}")
            
    # === API Settings ===
    
    def get_api_settings(self) -> Dict:
        """Get API configuration settings."""
        return self._config_cache.get('clients', {}).get('api_settings', {
            "timeout": 30,
            "max_retries": 3,
            "per_page": 100,
            "base_url_template": "https://k{client}.ciphersa.net"
        })
        
    def get_base_url_for_client(self, client_id: str) -> str:
        """Get base URL for a specific client."""
        api_settings = self.get_api_settings()
        template = api_settings.get('base_url_template', 'https://k{client}.ciphersa.net')
        return template.format(client=client_id)
        
    # === Processing Settings ===
    
    def get_processing_settings(self) -> Dict:
        """Get processing configuration settings."""
        return self._config_cache.get('clients', {}).get('processing_settings', {
            "technique_naming_format": "{technique}.{subtechnique}.{sub_subtechnique}",
            "include_disabled_rules": False,
            "excel_sheet_settings": {
                "max_column_width": 100,
                "wrap_text": True,
                "auto_filter": True
            }
        })
        
    def get_technique_naming_format(self) -> str:
        """Get the format string for technique naming."""
        processing_settings = self.get_processing_settings()
        return processing_settings.get('technique_naming_format', '{technique}.{subtechnique}.{sub_subtechnique}')
        
    def format_technique_name(self, technique: str = "", subtechnique: str = "", sub_subtechnique: str = "") -> str:
        """
        Format technique name according to configuration.
        
        Args:
            technique: Main technique name
            subtechnique: Sub-technique name  
            sub_subtechnique: Sub-sub-technique name
            
        Returns:
            Formatted technique name string
        """
        format_string = self.get_technique_naming_format()
        
        # Clean empty values
        parts = []
        if technique.strip():
            parts.append(technique.strip())
        if subtechnique.strip():
            parts.append(subtechnique.strip())
        if sub_subtechnique.strip():
            parts.append(sub_subtechnique.strip())
            
        # Join with dots, removing empty parts
        return ".".join(parts) if parts else ""
        
    # === Credentials Management ===
    
    def get_credentials(self) -> Dict[str, str]:
        """
        Get API credentials from environment variables or config file.
        
        Returns:
            Dictionary with username and password
        """
        # Priority 1: Environment variables
        username = os.environ.get("SRANK_API_USERNAME")
        password = os.environ.get("SRANK_API_PASSWORD")
        
        if username and password:
            return {"username": username, "password": password}
            
        # Priority 2: Config file
        if self.credentials_config_path.exists():
            try:
                with open(self.credentials_config_path, 'r', encoding='utf-8') as f:
                    creds = json.load(f)
                    return {
                        "username": creds.get("username", ""),
                        "password": creds.get("password", "")
                    }
            except Exception as e:
                self.logger.error(f"Failed to load credentials from config: {e}")
                
        # Priority 3: Empty (will trigger error in calling code)
        return {"username": "", "password": ""}
        
    def save_credentials(self, username: str, password: str) -> bool:
        """
        Save credentials to config file.
        
        Args:
            username: API username
            password: API password
            
        Returns:
            True if saved successfully
        """
        try:
            credentials = {
                "username": username,
                "password": password,
                "saved_at": str(datetime.now())
            }
            
            with open(self.credentials_config_path, 'w', encoding='utf-8') as f:
                json.dump(credentials, f, indent=2)
                
            # Set restrictive permissions on credentials file
            os.chmod(self.credentials_config_path, 0o600)
            
            self.logger.info("Credentials saved successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save credentials: {e}")
            return False
            
    # === System Settings ===
    
    def get_system_setting(self, key: str, default: Any = None) -> Any:
        """Get a system setting value."""
        return self._config_cache.get('system', {}).get(key, default)
        
    def get_log_level(self) -> str:
        """Get logging level."""
        return self.get_system_setting('log_level', 'INFO')
        
    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled."""
        return self.get_system_setting('debug_mode', False)
        
    # === Validation ===
    
    def validate_config(self) -> Dict[str, List[str]]:
        """
        Validate all configuration settings.
        
        Returns:
            Dictionary with validation errors by category
        """
        errors = {
            "clients": [],
            "api_settings": [],
            "credentials": [],
            "system": []
        }
        
        # Validate clients
        clients = self.get_clients(enabled_only=False)
        if not clients:
            errors["clients"].append("No clients configured")
            
        client_ids = [c.get('id') for c in clients]
        if len(client_ids) != len(set(client_ids)):
            errors["clients"].append("Duplicate client IDs found")
            
        # Validate API settings
        api_settings = self.get_api_settings()
        if not api_settings.get('base_url_template'):
            errors["api_settings"].append("Missing base_url_template")
            
        if api_settings.get('timeout', 0) <= 0:
            errors["api_settings"].append("Invalid timeout value")
            
        # Validate credentials
        creds = self.get_credentials()
        if not creds.get('username') or not creds.get('password'):
            errors["credentials"].append("Missing username or password")
            
        return {k: v for k, v in errors.items() if v}  # Return only categories with errors
        
    def print_config_summary(self):
        """Print a summary of current configuration."""
        print("📋 S-Rank Core Configuration Summary:")
        print("=" * 50)
        
        # Clients
        clients = self.get_clients()
        print(f"🏢 Clients: {len(clients)} enabled")
        for client in clients[:5]:  # Show first 5
            print(f"   • {client['id']} - {client.get('name', 'N/A')}")
        if len(clients) > 5:
            print(f"   ... and {len(clients) - 5} more")
            
        # API Settings
        api_settings = self.get_api_settings()
        print(f"\n🔗 API Settings:")
        print(f"   • Timeout: {api_settings.get('timeout', 'N/A')}s")
        print(f"   • Max Retries: {api_settings.get('max_retries', 'N/A')}")
        print(f"   • Per Page: {api_settings.get('per_page', 'N/A')}")
        
        # Processing Settings
        processing = self.get_processing_settings()
        print(f"\n⚙️  Processing Settings:")
        print(f"   • Technique Format: {processing.get('technique_naming_format', 'N/A')}")
        print(f"   • Include Disabled Rules: {processing.get('include_disabled_rules', 'N/A')}")
        
        # Credentials Status
        creds = self.get_credentials()
        has_creds = bool(creds.get('username') and creds.get('password'))
        print(f"\n🔐 Credentials: {'✅ Configured' if has_creds else '❌ Missing'}")
        
        print("=" * 50)