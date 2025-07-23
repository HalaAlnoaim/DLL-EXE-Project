#!/usr/bin/env python3
"""
S-Rank Core - Stage 1: Fetch Detection Rules (Fixed Version)
Fixed logic issues: security, error handling, validation, and configuration management.
"""

import os
import json
import requests
from datetime import datetime
from typing import List, Dict, Optional
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
import sys
from pathlib import Path

try:
    from rich.table import Table
    from rich.console import Console
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    print("Warning: rich library not available. Install with: pip install rich")

class Color:
    """ANSI color codes for console output."""
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"

class SecureRuleFetcher:
    """Secure and robust rule fetcher with improved error handling."""
    
    def __init__(self):
        self.setup_logging()
        self.load_configuration()
        self.validate_environment()
        self.setup_session()
        
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = os.environ.get("SRANK_LOG_LEVEL", "INFO")
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_configuration(self):
        """Load configuration from environment variables and config files."""
        # Get credentials from environment variables (more secure)
        self.username = os.environ.get("SRANK_API_USERNAME")
        self.password = os.environ.get("SRANK_API_PASSWORD")
        
        # Fallback to config file if environment variables not set
        if not self.username or not self.password:
            self.load_credentials_from_config()
            
        # Default configuration
        self.clients = self.load_clients_list()
        self.base_url_template = os.environ.get("SRANK_BASE_URL", "https://k{client}.ciphersa.net")
        self.timeout = int(os.environ.get("SRANK_TIMEOUT", "30"))
        self.max_retries = int(os.environ.get("SRANK_MAX_RETRIES", "3"))
        self.per_page = int(os.environ.get("SRANK_PER_PAGE", "100"))
        
        self.headers = {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
            "User-Agent": "S-Rank-Core/1.0"
        }
        
    def load_credentials_from_config(self):
        """Load credentials from config file as fallback."""
        config_paths = [
            os.path.join(os.path.dirname(__file__), "..", "config", "credentials.json"),
            os.path.join(os.path.expanduser("~"), ".srank", "credentials.json"),
            "credentials.json"
        ]
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        creds = json.load(f)
                        self.username = creds.get("username")
                        self.password = creds.get("password")
                        self.logger.info(f"Loaded credentials from {config_path}")
                        return
                except Exception as e:
                    self.logger.warning(f"Failed to load credentials from {config_path}: {e}")
                    
        # Final fallback (only for development - should be removed in production)
        if not self.username or not self.password:
            self.logger.warning("No credentials found in environment or config files. Using defaults (INSECURE!)")
            self.username = "s"  # Remove this in production
            self.password = "6"  # Remove this in production
            
    def load_clients_list(self):
        """Load clients list from configuration."""
        # Try to load from environment variable
        clients_env = os.environ.get("SRANK_CLIENTS")
        if clients_env:
            return [c.strip() for c in clients_env.split(",")]
            
        # Try to load from config file
        config_path = os.path.join(os.path.dirname(__file__), "..", "config", "clients.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    return config.get("clients", [])
            except Exception as e:
                self.logger.warning(f"Failed to load clients from config: {e}")
                
        # Default clients list
        return ["cipher", "ksf", "osh", "jda", "fa", "svc", "latis", "innova", "saip", "golfsaudi"]
        
    def validate_environment(self):
        """Validate environment variables and configuration."""
        # Check for required environment variables
        self.report_dir = os.environ.get("SRANK_REPORT_DIR")
        self.pipeline_timestamp = os.environ.get("SRANK_PIPELINE_TIMESTAMP")
        
        if not self.report_dir:
            raise ValueError("SRANK_REPORT_DIR not found. Please run this script via main.py")
            
        if not self.pipeline_timestamp:
            self.logger.warning("SRANK_PIPELINE_TIMESTAMP not found, using current timestamp")
            self.pipeline_timestamp = datetime.now().strftime("%Y_%m_%d_%H%M")
            
        # Create output directory
        self.output_dir = os.path.join(self.report_dir, f"Rules_{self.pipeline_timestamp}")
        
        # Clean and recreate output directory
        if os.path.exists(self.output_dir):
            import shutil
            shutil.rmtree(self.output_dir)
            
        os.makedirs(self.output_dir, exist_ok=True)
        self.logger.info(f"Output directory: {self.output_dir}")
        
    def setup_session(self):
        """Setup HTTP session with retry strategy and security settings."""
        self.session = requests.Session()
        
        # Setup authentication
        if self.username and self.password:
            self.session.auth = HTTPBasicAuth(self.username, self.password)
        else:
            raise ValueError("No valid credentials available")
            
        # Setup headers
        self.session.headers.update(self.headers)
        
        # Setup retry strategy
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Security settings
        self.session.verify = True  # Always verify SSL certificates
        
    def fetch_rules_for_client(self, client: str) -> Optional[List[Dict]]:
        """Fetch detection rules for a specific client with comprehensive error handling."""
        if not client or not client.strip():
            self.logger.error(f"Invalid client name: {client}")
            return None
            
        client = client.strip().lower()
        base_url = self.base_url_template.format(client=client)
        api_url = f"{base_url}/s/{client}/api/detection_engine/rules/_find"
        
        self.logger.info(f"Fetching rules for client: {client}")
        self.logger.debug(f"API URL: {api_url}")
        
        all_rules = []
        page = 1
        consecutive_failures = 0
        max_consecutive_failures = 3
        
        while True:
            params = {"page": page, "per_page": self.per_page}
            
            try:
                self.logger.debug(f"Fetching page {page} for client {client}")
                
                response = self.session.get(
                    api_url, 
                    params=params, 
                    timeout=self.timeout
                )
                
                # Check for authentication errors
                if response.status_code == 401:
                    self.logger.error(f"Authentication failed for client {client}")
                    break
                    
                # Check for authorization errors
                if response.status_code == 403:
                    self.logger.error(f"Access forbidden for client {client}")
                    break
                    
                # Check for not found errors
                if response.status_code == 404:
                    self.logger.error(f"API endpoint not found for client {client}")
                    break
                    
                # Raise for other HTTP errors
                response.raise_for_status()
                
                # Reset consecutive failures counter on success
                consecutive_failures = 0
                
                try:
                    data = response.json()
                except json.JSONDecodeError as e:
                    self.logger.error(f"Invalid JSON response for client {client}: {e}")
                    break
                    
                # Validate response structure
                if not isinstance(data, dict):
                    self.logger.error(f"Unexpected response format for client {client}")
                    break
                    
                batch = data.get("data", [])
                
                if not isinstance(batch, list):
                    self.logger.error(f"Unexpected data format for client {client}")
                    break
                    
                if not batch:
                    self.logger.info(f"No more rules found for client {client} (page {page})")
                    break
                    
                all_rules.extend(batch)
                self.logger.debug(f"Fetched {len(batch)} rules on page {page} for client {client}")
                
                # Check if we've reached the end
                if len(batch) < self.per_page:
                    self.logger.info(f"Reached end of results for client {client}")
                    break
                    
                page += 1
                
                # Safety check to prevent infinite loops
                if page > 1000:  # Arbitrary large number
                    self.logger.warning(f"Reached maximum page limit for client {client}")
                    break
                    
            except requests.exceptions.Timeout:
                consecutive_failures += 1
                self.logger.warning(f"Timeout for client {client} (attempt {consecutive_failures}/{max_consecutive_failures})")
                
                if consecutive_failures >= max_consecutive_failures:
                    self.logger.error(f"Too many consecutive timeouts for client {client}")
                    break
                    
            except requests.exceptions.ConnectionError as e:
                consecutive_failures += 1
                self.logger.warning(f"Connection error for client {client}: {e} (attempt {consecutive_failures}/{max_consecutive_failures})")
                
                if consecutive_failures >= max_consecutive_failures:
                    self.logger.error(f"Too many consecutive connection errors for client {client}")
                    break
                    
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed for client {client}: {e}")
                break
                
            except Exception as e:
                self.logger.error(f"Unexpected error for client {client}: {e}")
                break
                
        if all_rules:
            self.logger.info(f"Successfully fetched {len(all_rules)} rules for client {client}")
        else:
            self.logger.warning(f"No rules fetched for client {client}")
            
        return all_rules if all_rules else None
        
    def save_rules_to_file(self, client: str, rules: List[Dict]) -> Optional[str]:
        """Save rules to JSON file with proper error handling."""
        if not rules:
            self.logger.warning(f"No rules to save for client {client}")
            return None
            
        try:
            # Generate filename with current date
            date_str = datetime.now().strftime("%d%b%Y").lower()
            filename = f"{client}_rules_{date_str}.json"
            filepath = os.path.join(self.output_dir, filename)
            
            # Add metadata to the rules
            rules_with_metadata = {
                "metadata": {
                    "client": client,
                    "fetch_timestamp": datetime.now().isoformat(),
                    "pipeline_timestamp": self.pipeline_timestamp,
                    "total_rules": len(rules),
                    "api_version": "detection_engine/rules/_find"
                },
                "rules": rules
            }
            
            # Save with proper encoding and formatting
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(rules_with_metadata, f, indent=2, ensure_ascii=False)
                
            # Verify file was written correctly
            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                self.logger.info(f"Saved {len(rules)} rules for {client} to: {filepath}")
                return filepath
            else:
                self.logger.error(f"Failed to save rules for {client} - file empty or not created")
                return None
                
        except IOError as e:
            self.logger.error(f"IO error saving rules for {client}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error saving rules for {client}: {e}")
            return None
            
    def print_summary_table(self, summary: List[Dict]):
        """Print a summary table of rule statistics per client."""
        if RICH_AVAILABLE:
            self._print_rich_summary(summary)
        else:
            self._print_simple_summary(summary)
            
    def _print_rich_summary(self, summary: List[Dict]):
        """Print summary using rich library."""
        console = Console()
        table = Table(title="Detection Rules Summary by Cluster")

        table.add_column("Client", style="cyan")
        table.add_column("Enabled", justify="right", style="green")
        table.add_column("Disabled", justify="right", style="red")
        table.add_column("Total", justify="right", style="yellow")
        table.add_column("Status", style="magenta")

        for item in summary:
            status = "✅ Success" if item.get("success") else "❌ Failed"
            table.add_row(
                item["client"],
                str(item["enabled"]),
                str(item["disabled"]),
                str(item["total"]),
                status
            )

        console.print(table)
        
    def _print_simple_summary(self, summary: List[Dict]):
        """Print summary using simple text formatting."""
        print("\n" + "="*80)
        print("DETECTION RULES SUMMARY BY CLUSTER")
        print("="*80)
        print(f"{'Client':<15} {'Enabled':<10} {'Disabled':<10} {'Total':<10} {'Status':<15}")
        print("-"*80)
        
        for item in summary:
            status = "✅ Success" if item.get("success") else "❌ Failed"
            print(f"{item['client']:<15} {item['enabled']:<10} {item['disabled']:<10} {item['total']:<10} {status:<15}")
            
        print("="*80)
        
    def create_fetch_summary(self, summary: List[Dict]):
        """Create a detailed summary file of the fetch operation."""
        try:
            summary_data = {
                "fetch_summary": {
                    "timestamp": datetime.now().isoformat(),
                    "pipeline_timestamp": self.pipeline_timestamp,
                    "total_clients": len(summary),
                    "successful_clients": len([s for s in summary if s.get("success")]),
                    "failed_clients": len([s for s in summary if not s.get("success")]),
                    "total_rules": sum(s.get("total", 0) for s in summary),
                    "total_enabled": sum(s.get("enabled", 0) for s in summary),
                    "total_disabled": sum(s.get("disabled", 0) for s in summary)
                },
                "client_details": summary
            }
            
            summary_path = os.path.join(self.output_dir, "fetch_summary.json")
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
                
            self.logger.info(f"Fetch summary saved to: {summary_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to create fetch summary: {e}")
            
    def run(self):
        """Main execution method."""
        print(f"{Color.BOLD}S-Rank Core - Stage 1: Fetch Detection Rules{Color.ENDC}")
        print(f"Output directory: {self.output_dir}")
        print(f"Clients to process: {', '.join(self.clients)}")
        print()
        
        summary = []
        successful_clients = 0
        
        for client in self.clients:
            print(f"Processing client: {client}...")
            
            try:
                rules = self.fetch_rules_for_client(client)
                
                if rules is not None:
                    # Calculate statistics
                    enabled_count = sum(1 for r in rules if r.get("enabled", False))
                    disabled_count = len(rules) - enabled_count
                    
                    # Save rules to file
                    filepath = self.save_rules_to_file(client, rules)
                    
                    if filepath:
                        print(f"{Color.OKGREEN}[✓] Finished fetching rules for {client} → saved to: {filepath}{Color.ENDC}")
                        successful_clients += 1
                        success = True
                    else:
                        print(f"{Color.FAIL}[✗] Failed to save rules for {client}{Color.ENDC}")
                        success = False
                        
                    summary.append({
                        "client": client,
                        "enabled": enabled_count,
                        "disabled": disabled_count,
                        "total": len(rules),
                        "filepath": filepath if filepath else "N/A",
                        "success": success
                    })
                    
                else:
                    print(f"{Color.FAIL}[✗] Failed to fetch rules for {client}{Color.ENDC}")
                    summary.append({
                        "client": client,
                        "enabled": 0,
                        "disabled": 0,
                        "total": 0,
                        "filepath": "N/A",
                        "success": False
                    })
                    
            except Exception as e:
                print(f"{Color.FAIL}[✗] Error processing {client}: {e}{Color.ENDC}")
                self.logger.error(f"Error processing {client}: {e}")
                summary.append({
                    "client": client,
                    "enabled": 0,
                    "disabled": 0,
                    "total": 0,
                    "filepath": "N/A",
                    "success": False
                })
                
        # Print final summary
        print()
        self.print_summary_table(summary)
        self.create_fetch_summary(summary)
        
        print(f"\n{Color.BOLD}Summary:{Color.ENDC}")
        print(f"Successfully processed: {successful_clients}/{len(self.clients)} clients")
        
        if successful_clients == len(self.clients):
            print(f"{Color.OKGREEN}All clients processed successfully!{Color.ENDC}")
            return 0
        elif successful_clients > 0:
            print(f"{Color.WARNING}Partially completed with some errors.{Color.ENDC}")
            return 1
        else:
            print(f"{Color.FAIL}Failed to process any clients.{Color.ENDC}")
            return 2


def main():
    """Entry point for the fetch script."""
    try:
        fetcher = SecureRuleFetcher()
        return fetcher.run()
    except KeyboardInterrupt:
        print(f"\n{Color.WARNING}Operation cancelled by user.{Color.ENDC}")
        return 130
    except Exception as e:
        print(f"{Color.FAIL}Fatal error: {e}{Color.ENDC}")
        logging.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())