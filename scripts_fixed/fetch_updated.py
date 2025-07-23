#!/usr/bin/env python3
"""
S-Rank Core - Stage 1: Fetch Detection Rules (Updated Version)
Now with ConfigManager integration and enhanced technique handling.
"""

import os
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import requests
from requests.auth import HTTPBasicAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from config_manager import ConfigManager

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
    CYAN = "\033[96m"

class EnhancedRuleFetcher:
    """Enhanced rule fetcher with ConfigManager integration and technique processing."""
    
    def __init__(self):
        self.setup_logging()
        self.config_manager = ConfigManager()
        self.validate_environment()
        self.load_configuration()
        self.setup_session()
        
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = os.environ.get("SRANK_LOG_LEVEL", "INFO")
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        self.logger = logging.getLogger(__name__)
        
    def load_configuration(self):
        """Load configuration from ConfigManager."""
        # Get clients from config
        self.clients = self.config_manager.get_client_ids(enabled_only=True)
        
        # Get API settings
        api_settings = self.config_manager.get_api_settings()
        self.timeout = api_settings.get('timeout', 30)
        self.max_retries = api_settings.get('max_retries', 3)
        self.per_page = api_settings.get('per_page', 100)
        
        # Get credentials
        creds = self.config_manager.get_credentials()
        self.username = creds.get('username')
        self.password = creds.get('password')
        
        if not self.username or not self.password:
            raise ValueError("❌ No valid credentials found. Please set SRANK_API_USERNAME and SRANK_API_PASSWORD environment variables or configure credentials file.")
        
        # Setup headers
        self.headers = api_settings.get('headers', {
            "kbn-xsrf": "true",
            "Content-Type": "application/json",
            "User-Agent": "S-Rank-Core/2.0"
        })
        
        self.logger.info(f"Loaded configuration for {len(self.clients)} clients")
        
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
        self.session.auth = HTTPBasicAuth(self.username, self.password)
        
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
        self.session.verify = True
        
    def extract_nested_techniques(self, threats: List[Dict]) -> Dict[str, str]:
        """
        Extract and format nested MITRE techniques from threat data.
        
        Args:
            threats: List of threat objects from rule data
            
        Returns:
            Dictionary with formatted technique information
        """
        techniques = []
        subtechniques = []
        sub_subtechniques = []
        tactics = []
        frameworks = []
        
        for threat in threats:
            # Extract framework
            framework = threat.get("framework", "")
            if framework:
                frameworks.append(framework)
                
            # Extract tactic
            tactic = threat.get("tactic", {})
            if isinstance(tactic, dict):
                tactic_name = tactic.get("name", "")
                if tactic_name:
                    tactics.append(tactic_name)
                    
            # Extract techniques and subtechniques
            technique_list = threat.get("technique", [])
            if not isinstance(technique_list, list):
                technique_list = [technique_list] if technique_list else []
                
            for tech in technique_list:
                if not isinstance(tech, dict):
                    continue
                    
                # Main technique
                tech_id = tech.get("id", "")
                tech_name = tech.get("name", "")
                
                if tech_id and tech_name:
                    # Check if it's a main technique (no dots) or subtechnique (has dots)
                    if "." not in tech_id:
                        techniques.append(f"{tech_id}")
                    else:
                        subtechniques.append(f"{tech_id}")
                
                # Process sub-techniques
                subtechnique_list = tech.get("subtechnique", [])
                if not isinstance(subtechnique_list, list):
                    subtechnique_list = [subtechnique_list] if subtechnique_list else []
                    
                for subtech in subtechnique_list:
                    if isinstance(subtech, dict):
                        subtech_id = subtech.get("id", "")
                        subtech_name = subtech.get("name", "")
                        
                        if subtech_id:
                            # Check for nested sub-sub-techniques
                            if subtech_id.count(".") >= 2:  # T1234.001.002
                                sub_subtechniques.append(subtech_id)
                            elif subtech_id.count(".") == 1:  # T1234.001
                                subtechniques.append(subtech_id)
                            else:  # T1234
                                techniques.append(subtech_id)
                                
        # Use ConfigManager to format technique names
        formatted_techniques = []
        formatted_subtechniques = []
        formatted_sub_subtechniques = []
        
        # Process main techniques
        for tech_id in set(techniques):
            formatted_techniques.append(tech_id)
            
        # Process subtechniques  
        for subtech_id in set(subtechniques):
            formatted_subtechniques.append(subtech_id)
            
        # Process sub-subtechniques
        for sub_subtech_id in set(sub_subtechniques):
            formatted_sub_subtechniques.append(sub_subtech_id)
            
        return {
            "techniques": ", ".join(sorted(set(formatted_techniques))),
            "technique_ids": ", ".join(sorted(set(formatted_techniques))),
            "subtechniques": ", ".join(sorted(set(formatted_subtechniques))),
            "subtechnique_ids": ", ".join(sorted(set(formatted_subtechniques))),
            "sub_subtechniques": ", ".join(sorted(set(formatted_sub_subtechniques))),
            "sub_subtechnique_ids": ", ".join(sorted(set(formatted_sub_subtechniques))),
            "tactics": ", ".join(sorted(set(tactics))),
            "frameworks": ", ".join(sorted(set(frameworks)))
        }
        
    def process_rule_techniques(self, rule: Dict) -> Dict:
        """
        Process and enhance rule with properly formatted technique information.
        
        Args:
            rule: Raw rule data from API
            
        Returns:
            Enhanced rule with formatted technique data
        """
        # Extract original threat data
        threats = rule.get("threat", [])
        if not isinstance(threats, list):
            threats = [threats] if threats else []
            
        # Extract and format techniques
        technique_data = self.extract_nested_techniques(threats)
        
        # Create complete technique name using ConfigManager format
        # This will create names like "T1055.Process Injection.Dynamic-link Library Injection"
        complete_techniques = []
        
        # Combine techniques, subtechniques, and sub-subtechniques
        all_technique_ids = []
        if technique_data["technique_ids"]:
            all_technique_ids.extend(technique_data["technique_ids"].split(", "))
        if technique_data["subtechnique_ids"]:
            all_technique_ids.extend(technique_data["subtechnique_ids"].split(", "))
        if technique_data["sub_subtechnique_ids"]:
            all_technique_ids.extend(technique_data["sub_subtechnique_ids"].split(", "))
            
        # Format each technique according to config
        for tech_id in sorted(set(all_technique_ids)):
            if tech_id.strip():
                # Split technique ID to get parts
                parts = tech_id.split(".")
                if len(parts) >= 1:
                    # Use the technique ID as the formatted name for now
                    # In a real implementation, you'd look up the actual names
                    complete_techniques.append(tech_id)
        
        # Enhanced rule data
        enhanced_rule = rule.copy()
        enhanced_rule.update({
            "mitre_techniques_formatted": ", ".join(complete_techniques),
            "mitre_technique_ids": technique_data["technique_ids"],
            "mitre_subtechnique_ids": technique_data["subtechnique_ids"],
            "mitre_sub_subtechnique_ids": technique_data["sub_subtechnique_ids"],
            "mitre_tactics": technique_data["tactics"],
            "mitre_frameworks": technique_data["frameworks"],
            "technique_count": len([t for t in complete_techniques if t.strip()])
        })
        
        return enhanced_rule
        
    def fetch_rules_for_client(self, client_id: str) -> Optional[List[Dict]]:
        """Fetch detection rules for a specific client with enhanced processing."""
        if not client_id or not client_id.strip():
            self.logger.error(f"Invalid client ID: {client_id}")
            return None
            
        client_id = client_id.strip().lower()
        
        # Get base URL from config
        base_url = self.config_manager.get_base_url_for_client(client_id)
        api_url = f"{base_url}/s/{client_id}/api/detection_engine/rules/_find"
        
        # Get client config for display name
        client_config = self.config_manager.get_client_config(client_id)
        client_name = client_config.get('name', client_id) if client_config else client_id
        
        self.logger.info(f"Fetching rules for {client_name} ({client_id})")
        self.logger.debug(f"API URL: {api_url}")
        
        all_rules = []
        page = 1
        consecutive_failures = 0
        max_consecutive_failures = 3
        
        while True:
            params = {"page": page, "per_page": self.per_page}
            
            try:
                self.logger.debug(f"Fetching page {page} for client {client_id}")
                
                response = self.session.get(api_url, params=params, timeout=self.timeout)
                
                # Handle different HTTP status codes
                if response.status_code == 401:
                    self.logger.error(f"Authentication failed for client {client_id}")
                    break
                elif response.status_code == 403:
                    self.logger.error(f"Access forbidden for client {client_id}")
                    break
                elif response.status_code == 404:
                    self.logger.error(f"API endpoint not found for client {client_id}")
                    break
                    
                response.raise_for_status()
                consecutive_failures = 0
                
                try:
                    data = response.json()
                except json.JSONDecodeError as e:
                    self.logger.error(f"Invalid JSON response for client {client_id}: {e}")
                    break
                    
                if not isinstance(data, dict):
                    self.logger.error(f"Unexpected response format for client {client_id}")
                    break
                    
                batch = data.get("data", [])
                
                if not isinstance(batch, list):
                    self.logger.error(f"Unexpected data format for client {client_id}")
                    break
                    
                if not batch:
                    self.logger.info(f"No more rules found for client {client_id} (page {page})")
                    break
                    
                # Process each rule to enhance technique data
                enhanced_batch = []
                for rule in batch:
                    try:
                        enhanced_rule = self.process_rule_techniques(rule)
                        enhanced_batch.append(enhanced_rule)
                    except Exception as e:
                        self.logger.warning(f"Failed to process rule {rule.get('id', 'unknown')}: {e}")
                        enhanced_batch.append(rule)  # Use original rule as fallback
                        
                all_rules.extend(enhanced_batch)
                self.logger.debug(f"Fetched and processed {len(enhanced_batch)} rules on page {page}")
                
                if len(batch) < self.per_page:
                    self.logger.info(f"Reached end of results for client {client_id}")
                    break
                    
                page += 1
                
                # Safety check
                if page > 1000:
                    self.logger.warning(f"Reached maximum page limit for client {client_id}")
                    break
                    
            except requests.exceptions.Timeout:
                consecutive_failures += 1
                self.logger.warning(f"Timeout for client {client_id} (attempt {consecutive_failures}/{max_consecutive_failures})")
                if consecutive_failures >= max_consecutive_failures:
                    break
                    
            except requests.exceptions.ConnectionError as e:
                consecutive_failures += 1
                self.logger.warning(f"Connection error for client {client_id}: {e}")
                if consecutive_failures >= max_consecutive_failures:
                    break
                    
            except requests.exceptions.RequestException as e:
                self.logger.error(f"Request failed for client {client_id}: {e}")
                break
                
            except Exception as e:
                self.logger.error(f"Unexpected error for client {client_id}: {e}")
                break
                
        if all_rules:
            self.logger.info(f"Successfully fetched and processed {len(all_rules)} rules for {client_name}")
        else:
            self.logger.warning(f"No rules fetched for {client_name}")
            
        return all_rules if all_rules else None
        
    def save_rules_to_file(self, client_id: str, rules: List[Dict]) -> Optional[str]:
        """Save enhanced rules to JSON file."""
        if not rules:
            self.logger.warning(f"No rules to save for client {client_id}")
            return None
            
        try:
            # Get client config for metadata
            client_config = self.config_manager.get_client_config(client_id)
            client_name = client_config.get('name', client_id) if client_config else client_id
            
            # Generate filename
            date_str = datetime.now().strftime("%d%b%Y").lower()
            filename = f"{client_id}_rules_{date_str}.json"
            filepath = os.path.join(self.output_dir, filename)
            
            # Calculate statistics
            enabled_count = sum(1 for r in rules if r.get("enabled", False))
            technique_count = sum(1 for r in rules if r.get("technique_count", 0) > 0)
            
            # Enhanced metadata
            rules_with_metadata = {
                "metadata": {
                    "client_id": client_id,
                    "client_name": client_name,
                    "fetch_timestamp": datetime.now().isoformat(),
                    "pipeline_timestamp": self.pipeline_timestamp,
                    "total_rules": len(rules),
                    "enabled_rules": enabled_count,
                    "rules_with_techniques": technique_count,
                    "api_version": "detection_engine/rules/_find",
                    "processing_version": "2.0_enhanced_techniques",
                    "config_version": self.config_manager.get_technique_naming_format()
                },
                "rules": rules
            }
            
            # Save with proper encoding
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(rules_with_metadata, f, indent=2, ensure_ascii=False)
                
            # Verify file
            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                self.logger.info(f"Saved {len(rules)} enhanced rules for {client_name} to: {filepath}")
                return filepath
            else:
                self.logger.error(f"Failed to save rules for {client_name} - file empty or not created")
                return None
                
        except Exception as e:
            self.logger.error(f"Error saving rules for {client_id}: {e}")
            return None
            
    def print_summary_table(self, summary: List[Dict]):
        """Print enhanced summary table."""
        if RICH_AVAILABLE:
            self._print_rich_summary(summary)
        else:
            self._print_simple_summary(summary)
            
    def _print_rich_summary(self, summary: List[Dict]):
        """Print enhanced summary using rich library."""
        console = Console()
        table = Table(title="🔍 Detection Rules Summary - Enhanced Processing")

        table.add_column("Client", style="cyan")
        table.add_column("Name", style="blue")
        table.add_column("Enabled", justify="right", style="green")
        table.add_column("Disabled", justify="right", style="red")
        table.add_column("Total", justify="right", style="yellow")
        table.add_column("W/ Techniques", justify="right", style="magenta")
        table.add_column("Status", style="bold")

        for item in summary:
            status = "✅ Success" if item.get("success") else "❌ Failed"
            table.add_row(
                item["client_id"],
                item["client_name"][:20] + "..." if len(item["client_name"]) > 20 else item["client_name"],
                str(item["enabled"]),
                str(item["disabled"]),
                str(item["total"]),
                str(item.get("with_techniques", 0)),
                status
            )

        console.print(table)
        
    def _print_simple_summary(self, summary: List[Dict]):
        """Print enhanced summary using simple formatting."""
        print("\n" + "="*100)
        print("🔍 DETECTION RULES SUMMARY - ENHANCED PROCESSING")
        print("="*100)
        print(f"{'Client':<12} {'Name':<25} {'Enabled':<8} {'Disabled':<8} {'Total':<8} {'W/Tech':<8} {'Status':<12}")
        print("-"*100)
        
        for item in summary:
            status = "✅ Success" if item.get("success") else "❌ Failed"
            name = item["client_name"][:23] + ".." if len(item["client_name"]) > 25 else item["client_name"]
            print(f"{item['client_id']:<12} {name:<25} {item['enabled']:<8} {item['disabled']:<8} {item['total']:<8} {item.get('with_techniques', 0):<8} {status:<12}")
            
        print("="*100)
        
    def create_enhanced_summary(self, summary: List[Dict]):
        """Create enhanced summary with technique statistics."""
        try:
            total_rules = sum(s.get("total", 0) for s in summary)
            total_enabled = sum(s.get("enabled", 0) for s in summary)
            total_with_techniques = sum(s.get("with_techniques", 0) for s in summary)
            
            summary_data = {
                "fetch_summary": {
                    "timestamp": datetime.now().isoformat(),
                    "pipeline_timestamp": self.pipeline_timestamp,
                    "processing_version": "2.0_enhanced_techniques",
                    "total_clients": len(summary),
                    "successful_clients": len([s for s in summary if s.get("success")]),
                    "failed_clients": len([s for s in summary if not s.get("success")]),
                    "total_rules": total_rules,
                    "total_enabled": total_enabled,
                    "total_disabled": total_rules - total_enabled,
                    "rules_with_techniques": total_with_techniques,
                    "technique_coverage_rate": f"{(total_with_techniques/total_rules*100):.1f}%" if total_rules > 0 else "0%"
                },
                "client_details": summary,
                "configuration": {
                    "technique_naming_format": self.config_manager.get_technique_naming_format(),
                    "clients_processed": [s["client_id"] for s in summary if s.get("success")],
                    "api_settings": self.config_manager.get_api_settings()
                }
            }
            
            summary_path = os.path.join(self.output_dir, "fetch_summary_enhanced.json")
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
                
            self.logger.info(f"Enhanced fetch summary saved to: {summary_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to create enhanced summary: {e}")
            
    def run(self):
        """Main execution method with enhanced processing."""
        print(f"{Color.BOLD}🚀 S-Rank Core - Stage 1: Enhanced Rule Fetcher{Color.ENDC}")
        print(f"{Color.CYAN}📋 Configuration Summary:{Color.ENDC}")
        self.config_manager.print_config_summary()
        print(f"\n{Color.CYAN}📂 Output directory:{Color.ENDC} {self.output_dir}")
        print(f"{Color.CYAN}🏢 Clients to process:{Color.ENDC} {len(self.clients)}")
        print()
        
        summary = []
        successful_clients = 0
        
        for client_id in self.clients:
            client_config = self.config_manager.get_client_config(client_id)
            client_name = client_config.get('name', client_id) if client_config else client_id
            
            print(f"{Color.CYAN}Processing:{Color.ENDC} {client_name} ({client_id})...")
            
            try:
                rules = self.fetch_rules_for_client(client_id)
                
                if rules is not None:
                    # Calculate enhanced statistics
                    enabled_count = sum(1 for r in rules if r.get("enabled", False))
                    disabled_count = len(rules) - enabled_count
                    with_techniques_count = sum(1 for r in rules if r.get("technique_count", 0) > 0)
                    
                    # Save rules
                    filepath = self.save_rules_to_file(client_id, rules)
                    
                    if filepath:
                        print(f"{Color.OKGREEN}[✓] {client_name}: {len(rules)} rules ({enabled_count} enabled, {with_techniques_count} with techniques){Color.ENDC}")
                        successful_clients += 1
                        success = True
                    else:
                        print(f"{Color.FAIL}[✗] {client_name}: Failed to save rules{Color.ENDC}")
                        success = False
                        
                    summary.append({
                        "client_id": client_id,
                        "client_name": client_name,
                        "enabled": enabled_count,
                        "disabled": disabled_count,
                        "total": len(rules),
                        "with_techniques": with_techniques_count,
                        "filepath": filepath if filepath else "N/A",
                        "success": success
                    })
                    
                else:
                    print(f"{Color.FAIL}[✗] {client_name}: Failed to fetch rules{Color.ENDC}")
                    summary.append({
                        "client_id": client_id,
                        "client_name": client_name,
                        "enabled": 0,
                        "disabled": 0,
                        "total": 0,
                        "with_techniques": 0,
                        "filepath": "N/A",
                        "success": False
                    })
                    
            except Exception as e:
                print(f"{Color.FAIL}[✗] {client_name}: Error - {e}{Color.ENDC}")
                self.logger.error(f"Error processing {client_id}: {e}")
                summary.append({
                    "client_id": client_id,
                    "client_name": client_name,
                    "enabled": 0,
                    "disabled": 0,
                    "total": 0,
                    "with_techniques": 0,
                    "filepath": "N/A",
                    "success": False
                })
                
        # Print final summary
        print()
        self.print_summary_table(summary)
        self.create_enhanced_summary(summary)
        
        # Final status
        total_rules = sum(s.get("total", 0) for s in summary)
        total_with_techniques = sum(s.get("with_techniques", 0) for s in summary)
        
        print(f"\n{Color.BOLD}📊 Enhanced Processing Summary:{Color.ENDC}")
        print(f"   • Clients processed: {successful_clients}/{len(self.clients)}")
        print(f"   • Total rules fetched: {total_rules}")
        print(f"   • Rules with MITRE techniques: {total_with_techniques}")
        print(f"   • Technique coverage: {(total_with_techniques/total_rules*100):.1f}%" if total_rules > 0 else "   • Technique coverage: 0%")
        
        if successful_clients == len(self.clients):
            print(f"{Color.OKGREEN}🎉 All clients processed successfully with enhanced technique data!{Color.ENDC}")
            return 0
        elif successful_clients > 0:
            print(f"{Color.WARNING}⚠️  Partially completed with some errors.{Color.ENDC}")
            return 1
        else:
            print(f"{Color.FAIL}❌ Failed to process any clients.{Color.ENDC}")
            return 2


def main():
    """Entry point for the enhanced fetch script."""
    try:
        fetcher = EnhancedRuleFetcher()
        return fetcher.run()
    except KeyboardInterrupt:
        print(f"\n{Color.WARNING}⚠️  Operation cancelled by user.{Color.ENDC}")
        return 130
    except Exception as e:
        print(f"{Color.FAIL}💥 Fatal error: {e}{Color.ENDC}")
        logging.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())