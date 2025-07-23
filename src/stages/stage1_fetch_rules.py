"""
Stage 1: Fetch Detection Rules
Retrieves detection rules from client APIs and saves them as JSON files.
"""

import json
import os
import requests
from datetime import datetime
from typing import List, Dict, Optional


class RuleFetcher:
    """Fetches detection rules from client APIs."""
    
    def __init__(self, base_output_dir, logger):
        """
        Initialize rule fetcher.
        
        Args:
            base_output_dir (str): Base output directory
            logger: Logger instance
        """
        self.base_output_dir = base_output_dir
        self.logger = logger
        self.output_folder = os.path.join(base_output_dir, "01_client_rules")
        
        # Client configuration - In production, this would come from config files or environment
        self.clients_config = self._load_client_config()
        
    def _load_client_config(self):
        """
        Load client configuration for API endpoints and authentication.
        
        Returns:
            dict: Client configuration
        """
        # Default configuration - modify for your actual clients
        config = {
            "client_a": {
                "name": "Client A - Financial Services",
                "api_endpoint": "https://api.client-a.com/security/rules",
                "auth_type": "bearer",
                "api_key": os.getenv("CLIENT_A_API_KEY", ""),
                "enabled": True
            },
            "client_b": {
                "name": "Client B - Healthcare",
                "api_endpoint": "https://api.client-b.com/detection/rules",
                "auth_type": "basic",
                "username": os.getenv("CLIENT_B_USERNAME", ""),
                "password": os.getenv("CLIENT_B_PASSWORD", ""),
                "enabled": True
            },
            "client_c": {
                "name": "Client C - Technology",
                "api_endpoint": "https://api.client-c.com/v2/rules",
                "auth_type": "api_key",
                "api_key": os.getenv("CLIENT_C_API_KEY", ""),
                "enabled": True
            }
        }
        
        # Try to load from config file if it exists
        config_file = "config/clients.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    file_config = json.load(f)
                    config.update(file_config)
                self.logger.info(f"Loaded client configuration from {config_file}")
            except Exception as e:
                self.logger.warning(f"Could not load config file: {str(e)}")
                
        return config
        
    def fetch_client_rules(self, client_id: str) -> Optional[Dict]:
        """
        Fetch rules for a specific client.
        
        Args:
            client_id (str): Client identifier
            
        Returns:
            dict or None: Rules data or None if fetch fails
        """
        if client_id not in self.clients_config:
            self.logger.error(f"Unknown client: {client_id}")
            return None
            
        client_config = self.clients_config[client_id]
        
        if not client_config.get("enabled", False):
            self.logger.info(f"Client {client_id} is disabled, skipping")
            return None
            
        self.logger.info(f"Fetching rules for {client_config['name']}")
        
        try:
            # For demo purposes, we'll generate sample data
            # In production, replace this with actual API calls
            if not self._has_valid_credentials(client_config):
                self.logger.warning(f"No valid credentials for {client_id}, generating sample data")
                return self._generate_sample_rules(client_id, client_config)
            else:
                return self._fetch_from_api(client_config)
                
        except Exception as e:
            self.logger.error(f"Failed to fetch rules for {client_id}: {str(e)}")
            # Generate sample data as fallback
            return self._generate_sample_rules(client_id, client_config)
            
    def _has_valid_credentials(self, config):
        """Check if client has valid credentials configured."""
        auth_type = config.get("auth_type")
        
        if auth_type == "bearer" or auth_type == "api_key":
            return bool(config.get("api_key"))
        elif auth_type == "basic":
            return bool(config.get("username") and config.get("password"))
            
        return False
        
    def _fetch_from_api(self, config):
        """Fetch rules from actual API endpoint."""
        headers = {}
        auth = None
        
        # Set up authentication
        auth_type = config.get("auth_type")
        if auth_type == "bearer":
            headers["Authorization"] = f"Bearer {config['api_key']}"
        elif auth_type == "api_key":
            headers["X-API-Key"] = config["api_key"]
        elif auth_type == "basic":
            auth = (config["username"], config["password"])
            
        # Make API request
        response = requests.get(
            config["api_endpoint"],
            headers=headers,
            auth=auth,
            timeout=30
        )
        response.raise_for_status()
        
        return response.json()
        
    def _generate_sample_rules(self, client_id: str, config: Dict) -> Dict:
        """
        Generate sample detection rules for demonstration.
        
        Args:
            client_id (str): Client identifier
            config (dict): Client configuration
            
        Returns:
            dict: Sample rules data
        """
        # Sample MITRE techniques for variety
        sample_techniques = [
            {"id": "T1003", "name": "OS Credential Dumping", "tactic": "credential-access"},
            {"id": "T1055", "name": "Process Injection", "tactic": "privilege-escalation"},
            {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
            {"id": "T1071", "name": "Application Layer Protocol", "tactic": "command-and-control"},
            {"id": "T1078", "name": "Valid Accounts", "tactic": "persistence"},
            {"id": "T1082", "name": "System Information Discovery", "tactic": "discovery"},
            {"id": "T1087", "name": "Account Discovery", "tactic": "discovery"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "command-and-control"},
            {"id": "T1110", "name": "Brute Force", "tactic": "credential-access"},
            {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "initial-access"},
        ]
        
        rules = []
        
        # Generate 20-40 rules per client with variations
        num_rules = 25 + (hash(client_id) % 15)  # 25-40 rules
        
        for i in range(num_rules):
            technique = sample_techniques[i % len(sample_techniques)]
            
            # Vary which rules are enabled (85% enabled on average)
            is_enabled = (hash(f"{client_id}_{i}") % 100) < 85
            
            rule = {
                "id": f"{client_id.upper()}_RULE_{i+1:03d}",
                "name": f"{technique['name']} Detection - {config['name']}",
                "description": f"Detects suspicious activities related to {technique['name']} (MITRE {technique['id']})",
                "enabled": is_enabled,
                "severity": ["Low", "Medium", "High", "Critical"][hash(f"{client_id}_{i}") % 4],
                "mitre_tactic": technique["tactic"].title().replace("-", " "),
                "mitre_technique": technique["name"],
                "mitre_technique_id": technique["id"],
                "mitre_subtechnique": f"{technique['name']} - Variant {(i % 3) + 1}" if i % 3 == 0 else "",
                "mitre_subtechnique_id": f"{technique['id']}.{(i % 3) + 1:03d}" if i % 3 == 0 else "",
                "tags": [
                    technique["tactic"],
                    "mitre-attack",
                    client_id.replace("_", "-"),
                    "automated-detection"
                ],
                "mitre_framework": "Enterprise",
                "created_date": f"2024-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}",
                "last_modified": datetime.now().strftime("%Y-%m-%d"),
                "rule_type": ["Sigma", "KQL", "SPL", "YARA"][hash(f"{client_id}_{i}") % 4],
                "platforms": ["Windows", "Linux", "macOS", "Cloud"][:(hash(f"{client_id}_{i}") % 3) + 1],
                "confidence": ["Low", "Medium", "High"][hash(f"{client_id}_{i}") % 3],
                "false_positive_rate": ["Low", "Medium", "High"][hash(f"{client_id}_{i}") % 3]
            }
            
            rules.append(rule)
            
        return {
            "metadata": {
                "client_id": client_id,
                "client_name": config["name"],
                "fetched_at": datetime.now().isoformat(),
                "total_rules": len(rules),
                "enabled_rules": sum(1 for r in rules if r["enabled"]),
                "api_endpoint": config.get("api_endpoint", "N/A"),
                "data_type": "sample_generated"
            },
            "rules": rules
        }
        
    def save_client_rules(self, client_id: str, rules_data: Dict) -> str:
        """
        Save client rules to JSON file.
        
        Args:
            client_id (str): Client identifier
            rules_data (dict): Rules data to save
            
        Returns:
            str: Path to saved file
        """
        # Ensure output directory exists
        os.makedirs(self.output_folder, exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d")
        filename = f"{client_id}_rules_{timestamp}.json"
        filepath = os.path.join(self.output_folder, filename)
        
        # Save to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(rules_data, f, indent=2, ensure_ascii=False)
            
        self.logger.info(f"Saved {len(rules_data.get('rules', []))} rules for {client_id} to {filepath}")
        return filepath
        
    def fetch_all_clients(self) -> str:
        """
        Fetch rules for all enabled clients.
        
        Returns:
            str: Path to output folder containing all client files
        """
        self.logger.info("Starting to fetch rules for all clients")
        
        enabled_clients = [cid for cid, config in self.clients_config.items() 
                          if config.get("enabled", False)]
        
        if not enabled_clients:
            self.logger.warning("No enabled clients found")
            return self.output_folder
            
        successful_fetches = 0
        
        for client_id in enabled_clients:
            try:
                rules_data = self.fetch_client_rules(client_id)
                if rules_data:
                    self.save_client_rules(client_id, rules_data)
                    successful_fetches += 1
                else:
                    self.logger.error(f"No data retrieved for {client_id}")
                    
            except Exception as e:
                self.logger.error(f"Failed to process {client_id}: {str(e)}")
                
        self.logger.info(f"Successfully fetched rules for {successful_fetches}/{len(enabled_clients)} clients")
        
        # Create summary file
        self._create_summary_file(successful_fetches, len(enabled_clients))
        
        return self.output_folder
        
    def _create_summary_file(self, successful: int, total: int):
        """Create a summary file of the fetch operation."""
        summary = {
            "fetch_summary": {
                "timestamp": datetime.now().isoformat(),
                "total_clients": total,
                "successful_fetches": successful,
                "failed_fetches": total - successful,
                "output_folder": self.output_folder
            },
            "client_details": {}
        }
        
        # Add details for each client file
        for filename in os.listdir(self.output_folder):
            if filename.endswith('.json') and filename != 'fetch_summary.json':
                filepath = os.path.join(self.output_folder, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        summary["client_details"][filename] = {
                            "client_name": data.get("metadata", {}).get("client_name", "Unknown"),
                            "total_rules": data.get("metadata", {}).get("total_rules", 0),
                            "enabled_rules": data.get("metadata", {}).get("enabled_rules", 0),
                            "file_size_mb": round(os.path.getsize(filepath) / (1024*1024), 2)
                        }
                except:
                    continue
                    
        # Save summary
        summary_path = os.path.join(self.output_folder, "fetch_summary.json")
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
            
        self.logger.info(f"Created fetch summary: {summary_path}")
        
    def get_client_list(self) -> List[str]:
        """Get list of configured clients."""
        return list(self.clients_config.keys())
        
    def get_enabled_clients(self) -> List[str]:
        """Get list of enabled clients."""
        return [cid for cid, config in self.clients_config.items() 
                if config.get("enabled", False)]