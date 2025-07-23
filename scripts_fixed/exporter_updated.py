#!/usr/bin/env python3
"""
S-Rank Core - Stage 2: Enhanced Excel Exporter (Updated Version)
Now with ConfigManager integration and enhanced technique formatting.
"""

import os
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import pandas as pd
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
from openpyxl.utils.dataframe import dataframe_to_rows
from openpyxl.utils import get_column_letter
import logging

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from config_manager import ConfigManager

class Color:
    """ANSI color codes for console output."""
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[96m"

class EnhancedExcelExporter:
    """Enhanced Excel exporter with ConfigManager integration and technique formatting."""
    
    def __init__(self):
        self.setup_logging()
        self.config_manager = ConfigManager()
        self.validate_environment()
        self.load_configuration()
        
    def setup_logging(self):
        """Setup logging configuration."""
        log_level = os.environ.get("SRANK_LOG_LEVEL", "INFO")
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        self.logger = logging.getLogger(__name__)
        
    def validate_environment(self):
        """Validate environment variables and configuration."""
        # Get report directory from environment
        self.report_dir = os.environ.get("SRANK_REPORT_DIR")
        if not self.report_dir:
            raise ValueError("SRANK_REPORT_DIR not found. Please run this script via main.py")
            
        # Get pipeline timestamp
        self.pipeline_timestamp = os.environ.get("SRANK_PIPELINE_TIMESTAMP")
        if not self.pipeline_timestamp:
            self.logger.warning("SRANK_PIPELINE_TIMESTAMP not found, using current timestamp")
            self.pipeline_timestamp = datetime.now().strftime("%Y_%m_%d_%H%M")
            
        self.report_dir = Path(self.report_dir)
        
        # Find the latest Rules folder
        rules_folders = sorted(self.report_dir.glob("Rules_*"))
        if not rules_folders:
            raise FileNotFoundError("No Rules_* folder found in the provided report directory")
        self.latest_rules_folder = rules_folders[-1]
        
        # Create export folder with consistent timestamp
        self.export_dir = self.report_dir / f"Exported_Rules_{self.pipeline_timestamp}"
        self.export_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Input folder: {self.latest_rules_folder}")
        self.logger.info(f"Output folder: {self.export_dir}")
        
    def load_configuration(self):
        """Load configuration from ConfigManager."""
        # Get processing settings
        self.processing_settings = self.config_manager.get_processing_settings()
        
        # Get Excel sheet settings
        excel_settings = self.processing_settings.get('excel_sheet_settings', {})
        self.max_column_width = excel_settings.get('max_column_width', 100)
        self.wrap_text = excel_settings.get('wrap_text', True)
        self.auto_filter = excel_settings.get('auto_filter', True)
        
        # Enhanced column definitions with technique formatting
        self.excel_columns = [
            "NAME", 
            "DESCRIPTION", 
            "SEVERITY", 
            "MITRE TACTIC", 
            "MITRE TECHNIQUE",  # This will contain the formatted technique.subtechnique.sub_subtechnique
            "TECHNIQUE ID", 
            "MITRE SUBTECHNIQUE", 
            "SUBTECHNIQUE ID",
            "SUB-SUBTECHNIQUE ID",  # New column for sub-sub-techniques
            "TAGS", 
            "MITRE FRAMEWORK", 
            "CREATED AT"
        ]
        
        # Style settings
        self.header_fill = PatternFill(start_color="702386", end_color="702386", fill_type="solid")
        self.row_alt_fill = PatternFill(start_color="00AEA4", end_color="00AEA4", fill_type="solid")
        self.header_font = Font(bold=True, color="FFFFFF")
        self.default_font = Font(color="000000")
        self.summary_fill = PatternFill(start_color="66CC66", end_color="66CC66", fill_type="solid")
        
        self.logger.info("Loaded enhanced configuration for Excel export")
        
    def load_and_validate_json_file(self, json_file_path: Path) -> Optional[Dict]:
        """Load and validate JSON file with enhanced error handling."""
        if not json_file_path.exists():
            self.logger.error(f"JSON file not found: {json_file_path}")
            return None
            
        try:
            with open(json_file_path, encoding="utf-8") as f:
                data = json.load(f)
                
            # Validate structure
            if not isinstance(data, dict):
                self.logger.error(f"Invalid JSON structure in {json_file_path.name}")
                return None
                
            # Check for enhanced format (with metadata)
            if "metadata" in data and "rules" in data:
                self.logger.info(f"Loading enhanced format JSON: {json_file_path.name}")
                return data
            elif isinstance(data, list):
                # Legacy format - convert to enhanced format
                self.logger.info(f"Converting legacy format JSON: {json_file_path.name}")
                return {
                    "metadata": {
                        "client_id": json_file_path.stem.split('_')[0],
                        "legacy_format": True,
                        "total_rules": len(data)
                    },
                    "rules": data
                }
            else:
                self.logger.error(f"Unrecognized JSON format in {json_file_path.name}")
                return None
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in {json_file_path.name}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to load {json_file_path.name}: {e}")
            return None
            
    def format_technique_display_name(self, rule: Dict) -> str:
        """
        Format technique display name according to config.
        Creates format like: T1055.Process Injection.Dynamic-link Library Injection
        """
        # Check if rule has enhanced technique data
        if "mitre_techniques_formatted" in rule:
            return rule["mitre_techniques_formatted"]
            
        # Fallback to extracting from threat data
        return self.extract_and_format_techniques_legacy(rule)
        
    def extract_and_format_techniques_legacy(self, rule: Dict) -> str:
        """Extract and format techniques from legacy rule format."""
        threats = rule.get("threat", [])
        if not isinstance(threats, list):
            threats = [threats] if threats else []
            
        formatted_techniques = []
        
        for threat in threats:
            technique_list = threat.get("technique", [])
            if not isinstance(technique_list, list):
                technique_list = [technique_list] if technique_list else []
                
            for tech in technique_list:
                if not isinstance(tech, dict):
                    continue
                    
                # Get main technique info
                tech_id = tech.get("id", "")
                tech_name = tech.get("name", "")
                
                if tech_id:
                    # Process subtechniques
                    subtechnique_list = tech.get("subtechnique", [])
                    if not isinstance(subtechnique_list, list):
                        subtechnique_list = [subtechnique_list] if subtechnique_list else []
                        
                    if subtechnique_list:
                        for subtech in subtechnique_list:
                            if isinstance(subtech, dict):
                                subtech_id = subtech.get("id", "")
                                subtech_name = subtech.get("name", "")
                                
                                # Use ConfigManager to format
                                formatted_name = self.config_manager.format_technique_name(
                                    technique=tech_name,
                                    subtechnique=subtech_name
                                )
                                
                                if formatted_name:
                                    formatted_techniques.append(f"{subtech_id} - {formatted_name}")
                    else:
                        # Main technique only
                        if tech_name:
                            formatted_techniques.append(f"{tech_id} - {tech_name}")
                            
        return ", ".join(formatted_techniques) if formatted_techniques else ""
        
    def extract_enhanced_mitre_fields(self, rule: Dict) -> Dict[str, str]:
        """Extract enhanced MITRE fields with proper formatting."""
        # Check if rule has enhanced data
        if "mitre_technique_ids" in rule:
            return {
                "MITRE TACTIC": rule.get("mitre_tactics", ""),
                "MITRE TECHNIQUE": self.format_technique_display_name(rule),
                "TECHNIQUE ID": rule.get("mitre_technique_ids", ""),
                "MITRE SUBTECHNIQUE": rule.get("mitre_subtechnique_ids", ""),
                "SUBTECHNIQUE ID": rule.get("mitre_subtechnique_ids", ""),
                "SUB-SUBTECHNIQUE ID": rule.get("mitre_sub_subtechnique_ids", ""),
                "MITRE FRAMEWORK": rule.get("mitre_frameworks", "Enterprise")
            }
        else:
            # Legacy extraction
            return self.extract_mitre_fields_legacy(rule)
            
    def extract_mitre_fields_legacy(self, rule: Dict) -> Dict[str, str]:
        """Extract MITRE fields from legacy format."""
        threats = rule.get("threat", [])
        if not isinstance(threats, list):
            threats = [threats] if threats else []
            
        tactics, techniques, tech_ids, subtechs, subtech_ids, frameworks = set(), set(), set(), set(), set(), set()
        sub_subtech_ids = set()
        
        for threat in threats:
            if threat.get("framework"):
                frameworks.add(threat["framework"])
                
            tactic = threat.get("tactic", {}).get("name")
            if tactic:
                tactics.add(tactic)
                
            technique_list = threat.get("technique", [])
            if not isinstance(technique_list, list):
                technique_list = [technique_list] if technique_list else []
                
            for tech in technique_list:
                if not isinstance(tech, dict):
                    continue
                    
                tech_name = tech.get("name", "")
                tech_id = tech.get("id", "")
                
                if tech_name:
                    techniques.add(tech_name)
                if tech_id:
                    tech_ids.add(tech_id)
                    
                subtechnique_list = tech.get("subtechnique", [])
                if not isinstance(subtechnique_list, list):
                    subtechnique_list = [subtechnique_list] if subtechnique_list else []
                    
                for sub in subtechnique_list:
                    if isinstance(sub, dict):
                        sub_name = sub.get("name", "")
                        sub_id = sub.get("id", "")
                        
                        if sub_name:
                            subtechs.add(sub_name)
                        if sub_id:
                            # Check if it's a sub-sub-technique (has 2+ dots)
                            if sub_id.count(".") >= 2:
                                sub_subtech_ids.add(sub_id)
                            else:
                                subtech_ids.add(sub_id)
                                
        return {
            "MITRE TACTIC": ", ".join(sorted(tactics)),
            "MITRE TECHNIQUE": self.format_technique_display_name(rule),
            "TECHNIQUE ID": ", ".join(sorted(tech_ids)),
            "MITRE SUBTECHNIQUE": ", ".join(sorted(subtechs)),
            "SUBTECHNIQUE ID": ", ".join(sorted(subtech_ids)),
            "SUB-SUBTECHNIQUE ID": ", ".join(sorted(sub_subtech_ids)),
            "MITRE FRAMEWORK": ", ".join(sorted(frameworks)) or "Enterprise"
        }
        
    def process_rules_for_export(self, data: Dict) -> List[Dict]:
        """Process rules for Excel export with enhanced formatting."""
        rules = data.get("rules", [])
        client_metadata = data.get("metadata", {})
        
        # Filter enabled rules if configured
        if not self.processing_settings.get("include_disabled_rules", False):
            rules = [rule for rule in rules if rule.get("enabled", False)]
            self.logger.info(f"Filtered {len(rules)} enabled rules from {len(data.get('rules', []))} total rules")
        
        enabled_rules = []
        
        for rule in rules:
            try:
                # Extract enhanced MITRE fields
                mitre_fields = self.extract_enhanced_mitre_fields(rule)
                
                # Build enhanced rule record
                enhanced_rule = {
                    "NAME": rule.get("name", ""),
                    "DESCRIPTION": rule.get("description", ""),
                    "SEVERITY": rule.get("severity", ""),
                    "TAGS": ", ".join(rule.get("tags", [])) if isinstance(rule.get("tags"), list) else str(rule.get("tags", "")),
                    "CREATED AT": rule.get("created_at", "")
                }
                
                # Add MITRE fields
                enhanced_rule.update(mitre_fields)
                
                enabled_rules.append(enhanced_rule)
                
            except Exception as e:
                self.logger.warning(f"Failed to process rule {rule.get('id', 'unknown')}: {e}")
                # Add basic rule as fallback
                enabled_rules.append({
                    "NAME": rule.get("name", ""),
                    "DESCRIPTION": rule.get("description", ""),
                    "SEVERITY": rule.get("severity", ""),
                    "MITRE TACTIC": "",
                    "MITRE TECHNIQUE": "",
                    "TECHNIQUE ID": "",
                    "MITRE SUBTECHNIQUE": "",
                    "SUBTECHNIQUE ID": "",
                    "SUB-SUBTECHNIQUE ID": "",
                    "TAGS": ", ".join(rule.get("tags", [])) if isinstance(rule.get("tags"), list) else "",
                    "MITRE FRAMEWORK": "Enterprise",
                    "CREATED AT": rule.get("created_at", "")
                })
                
        return enabled_rules
        
    def create_enhanced_excel_file(self, rules_data: List[Dict], client_metadata: Dict, output_path: Path):
        """Create enhanced Excel file with multiple sheets and formatting."""
        try:
            wb = Workbook()
            ws = wb.active
            ws.title = "Enabled Rules"
            
            # Enhanced summary row
            total_rules = len(rules_data)
            techniques_count = len([r for r in rules_data if r.get("TECHNIQUE ID", "").strip()])
            
            ws.merge_cells(start_row=1, start_column=1, end_row=1, end_column=len(self.excel_columns))
            cell = ws.cell(row=1, column=1)
            cell.value = f"Total Detections: {total_rules} | With MITRE Techniques: {techniques_count} | Client: {client_metadata.get('client_name', 'Unknown')}"
            cell.fill = self.summary_fill
            cell.font = Font(bold=True)
            cell.alignment = Alignment(horizontal="center")
            
            # Create DataFrame and add to Excel
            df = pd.DataFrame(rules_data, columns=self.excel_columns)
            
            # Add data rows
            for r_idx, row in enumerate(dataframe_to_rows(df, index=False, header=True), start=2):
                for c_idx, val in enumerate(row, start=1):
                    cell = ws.cell(row=r_idx, column=c_idx, value=val)
                    cell.alignment = Alignment(wrap_text=self.wrap_text, vertical="center", horizontal="left")
                    
                    # Add borders
                    thin_border = Border(
                        left=Side(style='thin'), right=Side(style='thin'),
                        top=Side(style='thin'), bottom=Side(style='thin')
                    )
                    cell.border = thin_border
                    
                    # Apply styling
                    if r_idx == 2:  # Header row
                        cell.fill = self.header_fill
                        cell.font = self.header_font
                        cell.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
                    elif r_idx % 2 == 1:  # Odd rows
                        cell.fill = self.row_alt_fill
                        cell.font = self.default_font
                    else:  # Even rows
                        cell.font = self.default_font
                        
            # Auto-adjust column widths with enhanced logic
            self.adjust_column_widths(ws, df)
            
            # Add auto-filter if configured
            if self.auto_filter and len(df) > 0:
                ws.auto_filter.ref = f"A2:{get_column_letter(len(self.excel_columns))}{len(df) + 2}"
                
            # Add additional sheets
            self.add_summary_sheet(wb, rules_data, client_metadata)
            self.add_technique_analysis_sheet(wb, rules_data, client_metadata)
            
            # Save workbook
            wb.save(output_path)
            self.logger.info(f"Enhanced Excel file created: {output_path}")
            
            # Validate file creation
            if output_path.exists() and output_path.stat().st_size > 0:
                return True
            else:
                self.logger.error(f"Excel file validation failed: {output_path}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to create Excel file {output_path}: {e}")
            return False
            
    def adjust_column_widths(self, ws, df: pd.DataFrame):
        """Adjust column widths with enhanced logic."""
        for col_idx, column in enumerate(df.columns, start=1):
            # Calculate optimal width
            max_length = 0
            
            # Check header length
            max_length = max(max_length, len(str(column)))
            
            # Check data lengths
            for value in df[column].dropna():
                value_str = str(value)
                # For technique columns, allow more width
                if "TECHNIQUE" in column or "DESCRIPTION" in column:
                    max_length = max(max_length, min(len(value_str), 80))
                else:
                    max_length = max(max_length, len(value_str))
                    
            # Apply width with limits
            col_letter = get_column_letter(col_idx)
            adjusted_width = min(max_length + 2, self.max_column_width)
            
            # Minimum widths for specific columns
            if "TECHNIQUE" in column:
                adjusted_width = max(adjusted_width, 40)
            elif "DESCRIPTION" in column:
                adjusted_width = max(adjusted_width, 50)
            elif column in ["NAME", "TAGS"]:
                adjusted_width = max(adjusted_width, 25)
            else:
                adjusted_width = max(adjusted_width, 15)
                
            ws.column_dimensions[col_letter].width = adjusted_width
            
    def add_summary_sheet(self, wb: Workbook, rules_data: List[Dict], client_metadata: Dict):
        """Add enhanced summary sheet."""
        ws_summary = wb.create_sheet(title="Summary")
        
        # Client information
        summary_data = [
            ["S-Rank Core - Enhanced Detection Rules Export", ""],
            ["", ""],
            ["Client Information", ""],
            ["Client Name", client_metadata.get("client_name", "Unknown")],
            ["Client ID", client_metadata.get("client_id", "Unknown")],
            ["Export Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Processing Version", client_metadata.get("processing_version", "Standard")],
            ["", ""],
            ["Rule Statistics", ""],
            ["Total Enabled Rules", len(rules_data)],
            ["", ""],
        ]
        
        # Enhanced statistics
        severity_counts = {}
        tactic_counts = {}
        technique_counts = 0
        
        for rule in rules_data:
            # Severity distribution
            severity = rule.get("SEVERITY", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Tactic distribution
            tactics = rule.get("MITRE TACTIC", "")
            if tactics:
                for tactic in tactics.split(", "):
                    tactic = tactic.strip()
                    if tactic:
                        tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                        
            # Technique count
            if rule.get("TECHNIQUE ID", "").strip():
                technique_counts += 1
                
        # Add severity distribution
        summary_data.extend([
            ["Severity Distribution", ""],
        ])
        for severity, count in sorted(severity_counts.items()):
            summary_data.append([f"  {severity}", count])
            
        # Add tactic distribution
        summary_data.extend([
            ["", ""],
            ["MITRE Tactic Distribution", ""],
        ])
        for tactic, count in sorted(tactic_counts.items()):
            summary_data.append([f"  {tactic}", count])
            
        # Add technique statistics
        summary_data.extend([
            ["", ""],
            ["MITRE Technique Coverage", ""],
            ["Rules with Techniques", technique_counts],
            ["Coverage Rate", f"{(technique_counts/len(rules_data)*100):.1f}%" if rules_data else "0%"],
        ])
        
        # Write summary data
        for row_idx, row_data in enumerate(summary_data, start=1):
            for col_idx, value in enumerate(row_data, start=1):
                cell = ws_summary.cell(row=row_idx, column=col_idx, value=value)
                
                # Style headers
                if col_idx == 1 and value and not str(value).startswith("  "):
                    cell.font = Font(bold=True)
                    
        # Adjust column widths
        for col in range(1, 3):
            col_letter = get_column_letter(col)
            if col == 1:
                ws_summary.column_dimensions[col_letter].width = 40
            else:
                ws_summary.column_dimensions[col_letter].width = 20
                
    def add_technique_analysis_sheet(self, wb: Workbook, rules_data: List[Dict], client_metadata: Dict):
        """Add enhanced technique analysis sheet."""
        ws_tech = wb.create_sheet(title="Technique Analysis")
        
        # Analyze techniques
        technique_analysis = {}
        
        for rule in rules_data:
            techniques = rule.get("TECHNIQUE ID", "")
            if techniques:
                for tech_id in techniques.split(", "):
                    tech_id = tech_id.strip()
                    if tech_id:
                        if tech_id not in technique_analysis:
                            technique_analysis[tech_id] = {
                                "technique_id": tech_id,
                                "technique_name": "",  # Would be enhanced with MITRE database
                                "rule_count": 0,
                                "tactics": set(),
                                "severities": set()
                            }
                        
                        technique_analysis[tech_id]["rule_count"] += 1
                        
                        # Add tactics
                        tactics = rule.get("MITRE TACTIC", "")
                        if tactics:
                            for tactic in tactics.split(", "):
                                tactic = tactic.strip()
                                if tactic:
                                    technique_analysis[tech_id]["tactics"].add(tactic)
                                    
                        # Add severity
                        severity = rule.get("SEVERITY", "")
                        if severity:
                            technique_analysis[tech_id]["severities"].add(severity)
                            
        # Create analysis table
        headers = ["Technique ID", "Rule Count", "Tactics", "Severities", "Coverage Score"]
        
        # Write headers
        for col_idx, header in enumerate(headers, start=1):
            cell = ws_tech.cell(row=1, column=col_idx, value=header)
            cell.fill = self.header_fill
            cell.font = self.header_font
            cell.alignment = Alignment(horizontal="center", vertical="center")
            
        # Write data
        for row_idx, (tech_id, data) in enumerate(sorted(technique_analysis.items()), start=2):
            ws_tech.cell(row=row_idx, column=1, value=tech_id)
            ws_tech.cell(row=row_idx, column=2, value=data["rule_count"])
            ws_tech.cell(row=row_idx, column=3, value=", ".join(sorted(data["tactics"])))
            ws_tech.cell(row=row_idx, column=4, value=", ".join(sorted(data["severities"])))
            
            # Calculate coverage score (simple metric)
            coverage_score = min(data["rule_count"] * 10, 100)  # Cap at 100
            ws_tech.cell(row=row_idx, column=5, value=f"{coverage_score}%")
            
        # Adjust column widths
        widths = [20, 15, 40, 25, 20]
        for col_idx, width in enumerate(widths, start=1):
            col_letter = get_column_letter(col_idx)
            ws_tech.column_dimensions[col_letter].width = width
            
    def export_client_rules(self, json_file_path: Path) -> Optional[Path]:
        """Export enhanced rules for a single client."""
        try:
            # Load and validate JSON
            data = self.load_and_validate_json_file(json_file_path)
            if not data:
                return None
                
            # Extract client information
            client_metadata = data.get("metadata", {})
            client_id = client_metadata.get("client_id", json_file_path.stem.split('_')[0])
            
            # Get client config for name
            client_config = self.config_manager.get_client_config(client_id)
            if client_config:
                client_metadata["client_name"] = client_config.get("name", client_id)
            else:
                client_metadata["client_name"] = client_id
                
            # Process rules
            enabled_rules = self.process_rules_for_export(data)
            
            if not enabled_rules:
                self.logger.warning(f"No enabled rules found in {json_file_path.name}")
                return None
                
            # Generate output filename
            output_filename = f"{client_id}_enabled_rules_{self.pipeline_timestamp}.xlsx"
            output_path = self.export_dir / output_filename
            
            # Create Excel file
            success = self.create_enhanced_excel_file(enabled_rules, client_metadata, output_path)
            
            if success:
                self.logger.info(f"Successfully exported {len(enabled_rules)} rules for {client_metadata['client_name']}")
                return output_path
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to export {json_file_path.name}: {e}")
            return None
            
    def export_all_clients(self) -> bool:
        """Export all client JSON files to enhanced Excel format."""
        print(f"{Color.BOLD}🚀 S-Rank Core - Stage 2: Enhanced Excel Exporter{Color.ENDC}")
        print(f"{Color.CYAN}📋 Configuration Summary:{Color.ENDC}")
        self.config_manager.print_config_summary()
        print(f"\n{Color.CYAN}📂 Input folder:{Color.ENDC} {self.latest_rules_folder}")
        print(f"{Color.CYAN}📂 Output folder:{Color.ENDC} {self.export_dir}")
        print()
        
        # Find JSON files (exclude summary files)
        json_files = []
        for file_path in self.latest_rules_folder.glob("*.json"):
            if not file_path.name.startswith("fetch_summary"):
                json_files.append(file_path)
                
        if not json_files:
            print(f"{Color.FAIL}❌ No client JSON files found in {self.latest_rules_folder}{Color.ENDC}")
            return False
            
        print(f"{Color.CYAN}📄 Found {len(json_files)} client files to process{Color.ENDC}\n")
        
        successful_exports = 0
        export_summary = []
        
        for json_file in json_files:
            try:
                client_id = json_file.stem.split('_')[0]
                client_config = self.config_manager.get_client_config(client_id)
                client_name = client_config.get('name', client_id) if client_config else client_id
                
                print(f"{Color.CYAN}Processing:{Color.ENDC} {client_name} ({json_file.name})...")
                
                output_path = self.export_client_rules(json_file)
                
                if output_path:
                    print(f"{Color.OKGREEN}[✓] {client_name}: Exported to {output_path.name}{Color.ENDC}")
                    successful_exports += 1
                    
                    # Get file statistics
                    file_size_mb = output_path.stat().st_size / (1024 * 1024)
                    export_summary.append({
                        "client_id": client_id,
                        "client_name": client_name,
                        "input_file": json_file.name,
                        "output_file": output_path.name,
                        "file_size_mb": round(file_size_mb, 2),
                        "success": True
                    })
                else:
                    print(f"{Color.FAIL}[✗] {client_name}: Export failed{Color.ENDC}")
                    export_summary.append({
                        "client_id": client_id,
                        "client_name": client_name,
                        "input_file": json_file.name,
                        "output_file": "N/A",
                        "file_size_mb": 0,
                        "success": False
                    })
                    
            except Exception as e:
                print(f"{Color.FAIL}[✗] {json_file.name}: Error - {e}{Color.ENDC}")
                self.logger.error(f"Error processing {json_file.name}: {e}")
                
        # Create export summary
        self.create_export_summary(successful_exports, len(json_files), export_summary)
        
        # Final status
        print(f"\n{Color.BOLD}📊 Enhanced Export Summary:{Color.ENDC}")
        print(f"   • Files processed: {successful_exports}/{len(json_files)}")
        print(f"   • Success rate: {(successful_exports/len(json_files)*100):.1f}%")
        
        if successful_exports == len(json_files):
            print(f"{Color.OKGREEN}🎉 All clients exported successfully with enhanced formatting!{Color.ENDC}")
            return True
        elif successful_exports > 0:
            print(f"{Color.WARNING}⚠️  Partially completed with some errors.{Color.ENDC}")
            return True
        else:
            print(f"{Color.FAIL}❌ Failed to export any clients.{Color.ENDC}")
            return False
            
    def create_export_summary(self, successful: int, total: int, export_details: List[Dict]):
        """Create enhanced export summary."""
        try:
            summary_data = {
                "export_summary": {
                    "timestamp": datetime.now().isoformat(),
                    "pipeline_timestamp": self.pipeline_timestamp,
                    "processing_version": "2.0_enhanced_excel",
                    "input_folder": str(self.latest_rules_folder),
                    "output_folder": str(self.export_dir),
                    "total_files": total,
                    "successful_exports": successful,
                    "failed_exports": total - successful,
                    "success_rate": f"{(successful/total*100):.1f}%" if total > 0 else "0%"
                },
                "exported_files": export_details,
                "configuration": {
                    "technique_naming_format": self.config_manager.get_technique_naming_format(),
                    "excel_settings": self.processing_settings.get('excel_sheet_settings', {}),
                    "include_disabled_rules": self.processing_settings.get('include_disabled_rules', False)
                }
            }
            
            summary_path = self.export_dir / "export_summary_enhanced.json"
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
                
            self.logger.info(f"Enhanced export summary saved to: {summary_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to create export summary: {e}")


def main():
    """Entry point for the enhanced exporter script."""
    try:
        exporter = EnhancedExcelExporter()
        success = exporter.export_all_clients()
        return 0 if success else 1
    except KeyboardInterrupt:
        print(f"\n{Color.WARNING}⚠️  Operation cancelled by user.{Color.ENDC}")
        return 130
    except Exception as e:
        print(f"{Color.FAIL}💥 Fatal error: {e}{Color.ENDC}")
        logging.error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())