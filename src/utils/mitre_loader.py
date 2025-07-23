"""
MITRE ATT&CK framework data loader and processor.
Downloads and processes the official MITRE ATT&CK knowledge base.
"""

import json
import requests
import os
from datetime import datetime
from typing import Dict, List, Optional


class MitreAttackLoader:
    """Loads and processes MITRE ATT&CK framework data."""
    
    def __init__(self, cache_dir="data/mitre"):
        """
        Initialize MITRE ATT&CK loader.
        
        Args:
            cache_dir (str): Directory to cache MITRE data
        """
        self.cache_dir = cache_dir
        self.enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.data_file = os.path.join(cache_dir, "enterprise-attack.json")
        self.processed_file = os.path.join(cache_dir, "mitre_processed.json")
        
        # Ensure cache directory exists
        os.makedirs(cache_dir, exist_ok=True)
        
    def download_mitre_data(self, force_refresh=False):
        """
        Download the latest MITRE ATT&CK data.
        
        Args:
            force_refresh (bool): Force download even if cached data exists
            
        Returns:
            bool: True if download successful, False otherwise
        """
        if os.path.exists(self.data_file) and not force_refresh:
            # Check if file is less than 24 hours old
            file_age = datetime.now().timestamp() - os.path.getmtime(self.data_file)
            if file_age < 86400:  # 24 hours
                return True
                
        try:
            print("📥 Downloading MITRE ATT&CK Enterprise data...")
            response = requests.get(self.enterprise_url, timeout=30)
            response.raise_for_status()
            
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump(response.json(), f, indent=2)
                
            print("✅ MITRE ATT&CK data downloaded successfully")
            return True
            
        except Exception as e:
            print(f"❌ Failed to download MITRE data: {str(e)}")
            return False
            
    def load_raw_data(self):
        """
        Load raw MITRE ATT&CK data from file.
        
        Returns:
            dict or None: Raw MITRE data, or None if load fails
        """
        if not os.path.exists(self.data_file):
            if not self.download_mitre_data():
                return None
                
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"❌ Failed to load MITRE data: {str(e)}")
            return None
            
    def process_mitre_data(self):
        """
        Process raw MITRE data into structured format.
        
        Returns:
            dict: Processed MITRE data with techniques, tactics, etc.
        """
        raw_data = self.load_raw_data()
        if not raw_data:
            return None
            
        processed = {
            "metadata": {
                "last_updated": datetime.now().isoformat(),
                "source": self.enterprise_url,
                "version": raw_data.get("spec_version", "unknown")
            },
            "tactics": {},
            "techniques": {},
            "subtechniques": {},
            "groups": {},
            "software": {}
        }
        
        # Process all objects
        for obj in raw_data.get("objects", []):
            obj_type = obj.get("type")
            
            if obj_type == "x-mitre-tactic":
                self._process_tactic(obj, processed["tactics"])
            elif obj_type == "attack-pattern":
                if obj.get("x_mitre_is_subtechnique", False):
                    self._process_subtechnique(obj, processed["subtechniques"])
                else:
                    self._process_technique(obj, processed["techniques"])
            elif obj_type == "intrusion-set":
                self._process_group(obj, processed["groups"])
            elif obj_type == "malware" or obj_type == "tool":
                self._process_software(obj, processed["software"])
                
        # Save processed data
        with open(self.processed_file, 'w', encoding='utf-8') as f:
            json.dump(processed, f, indent=2)
            
        return processed
        
    def _process_tactic(self, obj, tactics_dict):
        """Process a MITRE tactic object."""
        tactic_id = obj.get("external_references", [{}])[0].get("external_id")
        if tactic_id:
            tactics_dict[tactic_id] = {
                "id": tactic_id,
                "name": obj.get("name"),
                "description": obj.get("description", ""),
                "shortname": obj.get("x_mitre_shortname", ""),
                "url": obj.get("external_references", [{}])[0].get("url", "")
            }
            
    def _process_technique(self, obj, techniques_dict):
        """Process a MITRE technique object."""
        technique_id = obj.get("external_references", [{}])[0].get("external_id")
        if technique_id:
            # Extract tactics this technique belongs to
            kill_chain_phases = obj.get("kill_chain_phases", [])
            tactics = [phase.get("phase_name") for phase in kill_chain_phases]
            
            techniques_dict[technique_id] = {
                "id": technique_id,
                "name": obj.get("name"),
                "description": obj.get("description", ""),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "detection": obj.get("x_mitre_detection", ""),
                "url": obj.get("external_references", [{}])[0].get("url", ""),
                "subtechniques": []  # Will be populated later
            }
            
    def _process_subtechnique(self, obj, subtechniques_dict):
        """Process a MITRE sub-technique object."""
        subtechnique_id = obj.get("external_references", [{}])[0].get("external_id")
        if subtechnique_id:
            # Extract parent technique ID
            parent_id = subtechnique_id.split('.')[0] if '.' in subtechnique_id else None
            
            kill_chain_phases = obj.get("kill_chain_phases", [])
            tactics = [phase.get("phase_name") for phase in kill_chain_phases]
            
            subtechniques_dict[subtechnique_id] = {
                "id": subtechnique_id,
                "parent_technique": parent_id,
                "name": obj.get("name"),
                "description": obj.get("description", ""),
                "tactics": tactics,
                "platforms": obj.get("x_mitre_platforms", []),
                "data_sources": obj.get("x_mitre_data_sources", []),
                "detection": obj.get("x_mitre_detection", ""),
                "url": obj.get("external_references", [{}])[0].get("url", "")
            }
            
    def _process_group(self, obj, groups_dict):
        """Process a MITRE group object."""
        group_id = obj.get("external_references", [{}])[0].get("external_id")
        if group_id:
            aliases = obj.get("aliases", [])
            groups_dict[group_id] = {
                "id": group_id,
                "name": obj.get("name"),
                "description": obj.get("description", ""),
                "aliases": aliases,
                "url": obj.get("external_references", [{}])[0].get("url", "")
            }
            
    def _process_software(self, obj, software_dict):
        """Process a MITRE software object."""
        software_id = obj.get("external_references", [{}])[0].get("external_id")
        if software_id:
            software_dict[software_id] = {
                "id": software_id,
                "name": obj.get("name"),
                "type": obj.get("type"),
                "description": obj.get("description", ""),
                "labels": obj.get("labels", []),
                "platforms": obj.get("x_mitre_platforms", []),
                "url": obj.get("external_references", [{}])[0].get("url", "")
            }
            
    def get_processed_data(self, force_refresh=False):
        """
        Get processed MITRE data, loading from cache if available.
        
        Args:
            force_refresh (bool): Force reprocessing of data
            
        Returns:
            dict: Processed MITRE data
        """
        if os.path.exists(self.processed_file) and not force_refresh:
            try:
                with open(self.processed_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Check if data is less than 24 hours old
                last_updated = datetime.fromisoformat(data["metadata"]["last_updated"])
                age = datetime.now() - last_updated
                if age.total_seconds() < 86400:  # 24 hours
                    return data
            except:
                pass
                
        # Process fresh data
        return self.process_mitre_data()
        
    def get_all_techniques(self, include_subtechniques=True):
        """
        Get all techniques and optionally subtechniques.
        
        Args:
            include_subtechniques (bool): Whether to include subtechniques
            
        Returns:
            dict: All techniques and subtechniques
        """
        data = self.get_processed_data()
        if not data:
            return {}
            
        all_techniques = data["techniques"].copy()
        
        if include_subtechniques:
            all_techniques.update(data["subtechniques"])
            
        return all_techniques
        
    def get_techniques_by_tactic(self, tactic_name):
        """
        Get all techniques for a specific tactic.
        
        Args:
            tactic_name (str): Name of the tactic
            
        Returns:
            dict: Techniques belonging to the tactic
        """
        all_techniques = self.get_all_techniques()
        tactic_techniques = {}
        
        for tech_id, tech_data in all_techniques.items():
            if tactic_name.lower() in [t.lower() for t in tech_data.get("tactics", [])]:
                tactic_techniques[tech_id] = tech_data
                
        return tactic_techniques
        
    def search_techniques(self, search_term):
        """
        Search techniques by name or description.
        
        Args:
            search_term (str): Term to search for
            
        Returns:
            dict: Matching techniques
        """
        all_techniques = self.get_all_techniques()
        matches = {}
        search_lower = search_term.lower()
        
        for tech_id, tech_data in all_techniques.items():
            if (search_lower in tech_data.get("name", "").lower() or 
                search_lower in tech_data.get("description", "").lower()):
                matches[tech_id] = tech_data
                
        return matches
        
    def get_technique_recommendations(self, technique_id):
        """
        Get logging and detection recommendations for a technique.
        
        Args:
            technique_id (str): MITRE technique ID
            
        Returns:
            dict: Recommendations and metadata
        """
        data = self.get_processed_data()
        if not data:
            return {}
            
        # Look in both techniques and subtechniques
        technique = data["techniques"].get(technique_id) or data["subtechniques"].get(technique_id)
        
        if not technique:
            return {}
            
        recommendations = {
            "technique_id": technique_id,
            "technique_name": technique.get("name"),
            "tactics": technique.get("tactics", []),
            "platforms": technique.get("platforms", []),
            "data_sources": technique.get("data_sources", []),
            "detection_guidance": technique.get("detection", ""),
            "mitre_url": technique.get("url", ""),
            "logging_recommendations": self._generate_logging_recommendations(technique)
        }
        
        return recommendations
        
    def _generate_logging_recommendations(self, technique):
        """Generate logging recommendations based on technique data."""
        recommendations = []
        
        data_sources = technique.get("data_sources", [])
        platforms = technique.get("platforms", [])
        
        # Generate recommendations based on data sources
        for source in data_sources:
            if "process" in source.lower():
                recommendations.append("Enable process creation logging (Sysmon Event ID 1, Windows Event ID 4688)")
            elif "file" in source.lower():
                recommendations.append("Enable file system monitoring (Sysmon Event ID 11)")
            elif "network" in source.lower():
                recommendations.append("Enable network connection logging (Sysmon Event ID 3)")
            elif "registry" in source.lower():
                recommendations.append("Enable registry monitoring (Sysmon Event IDs 12, 13, 14)")
            elif "authentication" in source.lower():
                recommendations.append("Enable authentication logging (Windows Event IDs 4624, 4625)")
                
        # Add platform-specific recommendations
        if "Windows" in platforms:
            recommendations.append("Configure Windows Event Logging and Sysmon")
        if "Linux" in platforms:
            recommendations.append("Configure auditd and system logging")
        if "macOS" in platforms:
            recommendations.append("Configure Unified Logging and Endpoint Security Framework")
            
        return list(set(recommendations))  # Remove duplicates