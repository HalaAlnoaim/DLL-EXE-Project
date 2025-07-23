#!/usr/bin/env python3
"""
S-Rank Core - Security Detection Coverage Analysis System
Main Pipeline Controller

This script manages the complete workflow for analyzing security detection
coverage against the MITRE ATT&CK framework across multiple clients.
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path

# Add the src directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from stages.stage1_fetch_rules import RuleFetcher
from stages.stage2_export_excel import ExcelExporter
from stages.stage3_gap_analyzer import GapAnalyzer
from stages.stage4_common_gaps import CommonGapsScanner
from utils.folder_manager import FolderManager
from utils.logger import setup_logger


class SRankCorePipeline:
    """Main pipeline controller for S-Rank Core system."""
    
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_output_dir = f"outputs/run_{self.timestamp}"
        self.folder_manager = FolderManager(self.base_output_dir)
        self.logger = setup_logger("SRankCore", self.base_output_dir)
        
    def display_menu(self):
        """Display the interactive menu for stage selection."""
        print("\n" + "="*60)
        print("    S-RANK CORE - Security Detection Coverage Analyzer")
        print("="*60)
        print("\nAvailable Options:")
        print("1. Run Full Pipeline (All Stages)")
        print("2. Stage 1: Fetch Detection Rules")
        print("3. Stage 2: Export Rules to Excel")
        print("4. Stage 3: Gap Analysis")
        print("5. Stage 4: Common Gaps Scanner")
        print("6. View Project Status")
        print("7. Exit")
        print("-"*60)
        
    def run_stage1(self):
        """Execute Stage 1: Fetch Detection Rules."""
        print("\n🔄 Starting Stage 1: Fetch Detection Rules...")
        self.logger.info("Starting Stage 1: Fetch Detection Rules")
        
        try:
            fetcher = RuleFetcher(self.base_output_dir, self.logger)
            clients_folder = fetcher.fetch_all_clients()
            print(f"✅ Stage 1 completed. Rules saved to: {clients_folder}")
            self.logger.info(f"Stage 1 completed successfully. Output: {clients_folder}")
            return clients_folder
        except Exception as e:
            print(f"❌ Stage 1 failed: {str(e)}")
            self.logger.error(f"Stage 1 failed: {str(e)}")
            return None
            
    def run_stage2(self, input_folder=None):
        """Execute Stage 2: Export Rules to Excel."""
        print("\n🔄 Starting Stage 2: Export Rules to Excel...")
        self.logger.info("Starting Stage 2: Export Rules to Excel")
        
        try:
            if not input_folder:
                input_folder = os.path.join(self.base_output_dir, "01_client_rules")
                
            exporter = ExcelExporter(self.base_output_dir, self.logger)
            excel_folder = exporter.export_all_clients(input_folder)
            print(f"✅ Stage 2 completed. Excel files saved to: {excel_folder}")
            self.logger.info(f"Stage 2 completed successfully. Output: {excel_folder}")
            return excel_folder
        except Exception as e:
            print(f"❌ Stage 2 failed: {str(e)}")
            self.logger.error(f"Stage 2 failed: {str(e)}")
            return None
            
    def run_stage3(self, input_folder=None):
        """Execute Stage 3: Gap Analysis."""
        print("\n🔄 Starting Stage 3: Gap Analysis...")
        self.logger.info("Starting Stage 3: Gap Analysis")
        
        try:
            if not input_folder:
                input_folder = os.path.join(self.base_output_dir, "02_excel_exports")
                
            analyzer = GapAnalyzer(self.base_output_dir, self.logger)
            analysis_folder = analyzer.analyze_all_clients(input_folder)
            print(f"✅ Stage 3 completed. Analysis reports saved to: {analysis_folder}")
            self.logger.info(f"Stage 3 completed successfully. Output: {analysis_folder}")
            return analysis_folder
        except Exception as e:
            print(f"❌ Stage 3 failed: {str(e)}")
            self.logger.error(f"Stage 3 failed: {str(e)}")
            return None
            
    def run_stage4(self, input_folder=None):
        """Execute Stage 4: Common Gaps Scanner."""
        print("\n🔄 Starting Stage 4: Common Gaps Scanner...")
        self.logger.info("Starting Stage 4: Common Gaps Scanner")
        
        try:
            if not input_folder:
                input_folder = os.path.join(self.base_output_dir, "03_gap_analysis")
                
            scanner = CommonGapsScanner(self.base_output_dir, self.logger)
            master_report = scanner.scan_common_gaps(input_folder)
            print(f"✅ Stage 4 completed. Master report saved to: {master_report}")
            self.logger.info(f"Stage 4 completed successfully. Output: {master_report}")
            return master_report
        except Exception as e:
            print(f"❌ Stage 4 failed: {str(e)}")
            self.logger.error(f"Stage 4 failed: {str(e)}")
            return None
            
    def run_full_pipeline(self):
        """Execute the complete pipeline (all stages)."""
        print("\n🚀 Starting Full Pipeline Execution...")
        self.logger.info("Starting full pipeline execution")
        
        # Create output directory structure
        self.folder_manager.create_output_structure()
        
        # Stage 1: Fetch Rules
        clients_folder = self.run_stage1()
        if not clients_folder:
            return False
            
        # Stage 2: Export to Excel
        excel_folder = self.run_stage2(clients_folder)
        if not excel_folder:
            return False
            
        # Stage 3: Gap Analysis
        analysis_folder = self.run_stage3(excel_folder)
        if not analysis_folder:
            return False
            
        # Stage 4: Common Gaps Scanner
        master_report = self.run_stage4(analysis_folder)
        if not master_report:
            return False
            
        print("\n🎉 Full Pipeline Completed Successfully!")
        print(f"📁 All outputs saved to: {self.base_output_dir}")
        self.logger.info("Full pipeline completed successfully")
        return True
        
    def view_status(self):
        """Display current project status."""
        print("\n📊 Project Status:")
        print(f"Current run directory: {self.base_output_dir}")
        
        if os.path.exists(self.base_output_dir):
            subdirs = [d for d in os.listdir(self.base_output_dir) if os.path.isdir(os.path.join(self.base_output_dir, d))]
            print(f"Existing output folders: {subdirs}")
        else:
            print("No output directory created yet.")
            
    def run(self):
        """Main execution loop with interactive menu."""
        while True:
            self.display_menu()
            choice = input("\nEnter your choice (1-7): ").strip()
            
            if choice == '1':
                self.run_full_pipeline()
            elif choice == '2':
                self.run_stage1()
            elif choice == '3':
                self.run_stage2()
            elif choice == '4':
                self.run_stage3()
            elif choice == '5':
                self.run_stage4()
            elif choice == '6':
                self.view_status()
            elif choice == '7':
                print("\n👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please select 1-7.")
                
            input("\nPress Enter to continue...")


def main():
    """Entry point for the S-Rank Core system."""
    try:
        pipeline = SRankCorePipeline()
        pipeline.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user.")
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()