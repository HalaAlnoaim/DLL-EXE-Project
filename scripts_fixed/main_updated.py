#!/usr/bin/env python3
"""
S-Rank Core - Enhanced Pipeline Controller (Updated Version)
Now with ConfigManager integration and enhanced processing capabilities.
"""

import os
import sys
import json
import subprocess
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import shutil
import logging

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from config_manager import ConfigManager

try:
    from rich.table import Table
    from rich.console import Console
    from rich.prompt import Prompt, Confirm
    from rich.panel import Panel
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
    MAGENTA = "\033[95m"

class EnhancedPipelineController:
    """Enhanced pipeline controller with ConfigManager integration."""
    
    def __init__(self):
        self.setup_logging()
        self.config_manager = ConfigManager()
        self.validate_configuration()
        self.setup_pipeline()
        
    def setup_logging(self):
        """Setup enhanced logging configuration."""
        log_level = self.config_manager.get_log_level()
        logging.basicConfig(
            level=getattr(logging, log_level.upper()),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        self.logger = logging.getLogger(__name__)
        
    def validate_configuration(self):
        """Validate configuration and show any issues."""
        validation_errors = self.config_manager.validate_config()
        
        if validation_errors:
            print(f"{Color.WARNING}⚠️  Configuration validation found issues:{Color.ENDC}")
            for category, errors in validation_errors.items():
                print(f"{Color.WARNING}  {category.upper()}:{Color.ENDC}")
                for error in errors:
                    print(f"    - {error}")
            print()
            
            # Check if critical errors exist
            critical_categories = ['credentials']
            has_critical_errors = any(cat in validation_errors for cat in critical_categories)
            
            if has_critical_errors:
                if not self._prompt_continue_with_errors():
                    print(f"{Color.FAIL}❌ Pipeline aborted due to configuration errors.{Color.ENDC}")
                    sys.exit(1)
        else:
            self.logger.info("Configuration validation passed")
            
    def _prompt_continue_with_errors(self) -> bool:
        """Prompt user to continue despite configuration errors."""
        if RICH_AVAILABLE:
            return Confirm.ask("Continue despite configuration errors?", default=False)
        else:
            response = input("Continue despite configuration errors? (y/N): ").strip().lower()
            return response in ['y', 'yes']
            
    def setup_pipeline(self):
        """Setup enhanced pipeline configuration."""
        # Enhanced stage definitions
        self.stages = {
            "1": {
                "name": "Fetch Detection Rules",
                "script": "fetch_updated.py",
                "description": "Fetch detection rules from client APIs with enhanced technique processing",
                "dependencies": [],
                "output_folder": "Rules_*",
                "required": True,
                "estimated_time": "2-5 minutes per client"
            },
            "2": {
                "name": "Export to Excel",
                "script": "exporter_updated.py", 
                "description": "Convert JSON rules to enhanced Excel format with technique formatting",
                "dependencies": ["1"],
                "output_folder": "Exported_Rules_*",
                "required": False,
                "estimated_time": "30-60 seconds per client"
            },
            "3": {
                "name": "Gap Analysis", 
                "script": "GapsAnalyzer_updated.py",
                "description": "Analyze MITRE coverage gaps using enhanced technique data",
                "dependencies": ["2"],
                "output_folder": "Reports_*",
                "required": False,
                "estimated_time": "1-2 minutes per client"
            },
            "4": {
                "name": "Common Gaps Scanner",
                "script": "GapsScanner_updated.py", 
                "description": "Identify common gaps across all clients with aggregated analysis",
                "dependencies": ["3"],
                "output_folder": "CommonGaps_*",
                "required": False,
                "estimated_time": "30-90 seconds"
            }
        }
        
        # Get workspace from config or create default
        self.workspace_dir = Path(os.environ.get("SRANK_WORKSPACE", "S-Rank_Reports"))
        self.scripts_dir = Path(__file__).parent
        
        # Pipeline settings
        self.pipeline_timestamp = datetime.now().strftime("%Y_%m_%d_%H%M")
        self.timeout_seconds = 300  # 5 minutes default timeout
        
        # Enhanced environment setup
        self.setup_environment_variables()
        
    def setup_environment_variables(self):
        """Setup enhanced environment variables for pipeline."""
        # Create timestamped workspace
        timestamped_workspace = self.workspace_dir / f"Pipeline_{self.pipeline_timestamp}"
        timestamped_workspace.mkdir(parents=True, exist_ok=True)
        
        # Set environment variables
        os.environ["SRANK_REPORT_DIR"] = str(timestamped_workspace)
        os.environ["SRANK_PIPELINE_TIMESTAMP"] = self.pipeline_timestamp
        os.environ["SRANK_WORKSPACE"] = str(self.workspace_dir)
        
        # Copy config manager settings to environment
        if self.config_manager.is_debug_mode():
            os.environ["SRANK_DEBUG"] = "true"
            os.environ["SRANK_LOG_LEVEL"] = "DEBUG"
        else:
            os.environ["SRANK_LOG_LEVEL"] = self.config_manager.get_log_level()
            
        # API credentials (if available)
        creds = self.config_manager.get_credentials()
        if creds.get('username') and creds.get('password'):
            os.environ["SRANK_API_USERNAME"] = creds['username']
            os.environ["SRANK_API_PASSWORD"] = creds['password']
            
        self.report_dir = timestamped_workspace
        self.logger.info(f"Pipeline workspace: {timestamped_workspace}")
        
    def print_enhanced_welcome(self):
        """Print enhanced welcome message with configuration info."""
        if RICH_AVAILABLE:
            console = Console()
            welcome_text = f"""
[bold magenta]🎯 S-Rank Core Enhanced Pipeline v2.0[/bold magenta]

[bold cyan]🏢 Client Configuration:[/bold cyan]
• Total Clients: {len(self.config_manager.get_clients())} enabled
• Active Clients: {', '.join(self.config_manager.get_client_ids()[:5])}{'...' if len(self.config_manager.get_client_ids()) > 5 else ''}

[bold cyan]⚙️  Processing Configuration:[/bold cyan]
• Technique Format: {self.config_manager.get_technique_naming_format()}
• Excel Auto-Filter: {self.config_manager.get_processing_settings().get('excel_sheet_settings', {}).get('auto_filter', True)}
• Include Disabled Rules: {self.config_manager.get_processing_settings().get('include_disabled_rules', False)}

[bold cyan]📂 Workspace:[/bold cyan]
• Report Directory: {self.report_dir}
• Pipeline Timestamp: {self.pipeline_timestamp}
            """
            console.print(Panel(welcome_text, border_style="cyan"))
        else:
            print(f"\n{Color.BOLD}{Color.MAGENTA}🎯 S-RANK CORE ENHANCED PIPELINE v2.0{Color.ENDC}")
            print("=" * 80)
            print(f"{Color.CYAN}🏢 Clients:{Color.ENDC} {len(self.config_manager.get_clients())} enabled")
            print(f"{Color.CYAN}📂 Workspace:{Color.ENDC} {self.report_dir}")
            print(f"{Color.CYAN}⚙️  Processing:{Color.ENDC} Enhanced technique formatting enabled")
            print("=" * 80 + "\n")
            
    def print_enhanced_stage_menu(self):
        """Print enhanced stage selection menu."""
        if RICH_AVAILABLE:
            console = Console()
            table = Table(title="🚀 Available Pipeline Stages", show_header=True, header_style="bold magenta")
            table.add_column("Stage", style="cyan", width=8)
            table.add_column("Name", style="green", width=25)
            table.add_column("Description", style="blue", width=40)
            table.add_column("Dependencies", style="yellow", width=12)
            table.add_column("Est. Time", style="white", width=15)
            
            for stage_id, stage_info in self.stages.items():
                deps = ", ".join(stage_info["dependencies"]) if stage_info["dependencies"] else "None"
                required_mark = " *" if stage_info["required"] else ""
                
                table.add_row(
                    stage_id,
                    stage_info["name"] + required_mark,
                    stage_info["description"],
                    deps,
                    stage_info["estimated_time"]
                )
                
            console.print(table)
            console.print("\n[bold white]* Required stages[/bold white]")
            console.print("[bold cyan]Options: Single stage (1-4), Multiple stages (1,3), Range (1-3), All stages (all)[/bold cyan]")
        else:
            print(f"\n{Color.BOLD}🚀 AVAILABLE PIPELINE STAGES:{Color.ENDC}")
            print("=" * 100)
            print(f"{'Stage':<8} {'Name':<30} {'Description':<45} {'Dependencies':<15}")
            print("-" * 100)
            
            for stage_id, stage_info in self.stages.items():
                deps = ", ".join(stage_info["dependencies"]) if stage_info["dependencies"] else "None"
                required_mark = " *" if stage_info["required"] else ""
                name = (stage_info["name"] + required_mark)[:29]
                desc = stage_info["description"][:44]
                
                print(f"{stage_id:<8} {name:<30} {desc:<45} {deps:<15}")
                
            print("\n* Required stages")
            print("Options: Single (1), Multiple (1,3), Range (1-3), All (all)")
            
    def get_stage_selection(self) -> List[str]:
        """Get enhanced stage selection from user."""
        while True:
            if RICH_AVAILABLE:
                selection = Prompt.ask("\n🎯 Select stages to run", default="all")
            else:
                selection = input(f"\n{Color.CYAN}🎯 Select stages to run (default: all):{Color.ENDC} ").strip() or "all"
                
            try:
                if selection.lower() == "all":
                    return list(self.stages.keys())
                elif "," in selection:
                    # Multiple stages: 1,3,4
                    stages = []
                    for s in selection.split(","):
                        s = s.strip()
                        if s in self.stages:
                            stages.append(s)
                        else:
                            raise ValueError(f"Invalid stage: {s}")
                    return stages
                elif "-" in selection:
                    # Range: 1-3
                    start, end = selection.split("-")
                    start, end = int(start.strip()), int(end.strip())
                    stages = []
                    for i in range(start, end + 1):
                        if str(i) in self.stages:
                            stages.append(str(i))
                    return stages
                else:
                    # Single stage: 1
                    if selection in self.stages:
                        return [selection]
                    else:
                        raise ValueError(f"Invalid stage: {selection}")
                        
            except ValueError as e:
                print(f"{Color.FAIL}❌ Invalid selection: {e}{Color.ENDC}")
                print(f"{Color.CYAN}Valid options: 1-4, 1,3, 1-3, all{Color.ENDC}")
                
    def resolve_dependencies(self, selected_stages: List[str]) -> List[str]:
        """Resolve stage dependencies and return execution order."""
        execution_order = []
        resolved = set()
        
        def resolve_stage(stage_id: str):
            if stage_id in resolved:
                return
                
            # Resolve dependencies first
            for dep_id in self.stages[stage_id]["dependencies"]:
                if dep_id not in resolved:
                    resolve_stage(dep_id)
                    
            if stage_id not in execution_order:
                execution_order.append(stage_id)
            resolved.add(stage_id)
            
        # Resolve all selected stages
        for stage_id in selected_stages:
            resolve_stage(stage_id)
            
        return execution_order
        
    def check_stage_prerequisites(self, stage_id: str) -> bool:
        """Check if stage prerequisites are met."""
        stage_info = self.stages[stage_id]
        
        # Check if dependency outputs exist
        for dep_id in stage_info["dependencies"]:
            dep_output_pattern = self.stages[dep_id]["output_folder"]
            
            # Look for output folders matching pattern
            matching_folders = list(self.report_dir.glob(dep_output_pattern))
            if not matching_folders:
                self.logger.warning(f"Stage {stage_id} dependency {dep_id} output not found")
                return False
                
        return True
        
    def execute_stage(self, stage_id: str) -> bool:
        """Execute enhanced pipeline stage with monitoring."""
        stage_info = self.stages[stage_id]
        script_path = self.scripts_dir / stage_info["script"]
        
        if not script_path.exists():
            self.logger.error(f"Script not found: {script_path}")
            return False
            
        print(f"\n{Color.BOLD}🚀 Executing Stage {stage_id}: {stage_info['name']}{Color.ENDC}")
        print(f"{Color.CYAN}Description:{Color.ENDC} {stage_info['description']}")
        print(f"{Color.CYAN}Estimated time:{Color.ENDC} {stage_info['estimated_time']}")
        print(f"{Color.CYAN}Script:{Color.ENDC} {stage_info['script']}")
        
        start_time = time.time()
        
        try:
            # Enhanced command execution
            cmd = [sys.executable, str(script_path)]
            
            self.logger.info(f"Executing: {' '.join(cmd)}")
            
            # Execute with enhanced monitoring
            result = subprocess.run(
                cmd,
                cwd=self.scripts_dir,
                capture_output=False,  # Let output go to console
                text=True,
                timeout=self.timeout_seconds,
                env=os.environ.copy()
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode == 0:
                print(f"{Color.OKGREEN}✅ Stage {stage_id} completed successfully in {execution_time:.1f}s{Color.ENDC}")
                self.logger.info(f"Stage {stage_id} completed successfully")
                return True
            else:
                print(f"{Color.FAIL}❌ Stage {stage_id} failed with return code {result.returncode}{Color.ENDC}")
                self.logger.error(f"Stage {stage_id} failed with return code {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"{Color.FAIL}❌ Stage {stage_id} timed out after {self.timeout_seconds}s{Color.ENDC}")
            self.logger.error(f"Stage {stage_id} timed out")
            return False
        except Exception as e:
            print(f"{Color.FAIL}❌ Stage {stage_id} error: {e}{Color.ENDC}")
            self.logger.error(f"Stage {stage_id} error: {e}")
            return False
            
    def create_enhanced_pipeline_summary(self, execution_results: Dict[str, Dict[str, Any]]):
        """Create enhanced pipeline execution summary."""
        try:
            # Calculate overall statistics
            total_stages = len(execution_results)
            successful_stages = len([r for r in execution_results.values() if r['success']])
            total_time = sum(r['execution_time'] for r in execution_results.values())
            
            # Get client statistics from config
            client_count = len(self.config_manager.get_clients())
            
            summary_data = {
                "pipeline_summary": {
                    "timestamp": datetime.now().isoformat(),
                    "pipeline_timestamp": self.pipeline_timestamp,
                    "version": "2.0_enhanced_processing",
                    "workspace": str(self.report_dir),
                    "total_execution_time": f"{total_time:.1f}s",
                    "stages_executed": total_stages,
                    "stages_successful": successful_stages,
                    "stages_failed": total_stages - successful_stages,
                    "success_rate": f"{(successful_stages/total_stages*100):.1f}%" if total_stages > 0 else "0%",
                    "client_count": client_count
                },
                "stage_results": execution_results,
                "configuration": {
                    "clients": [{"id": c["id"], "name": c["name"]} for c in self.config_manager.get_clients()],
                    "technique_naming_format": self.config_manager.get_technique_naming_format(),
                    "processing_settings": self.config_manager.get_processing_settings(),
                    "api_settings": {k: v for k, v in self.config_manager.get_api_settings().items() if k != 'headers'}
                },
                "output_folders": [
                    str(folder.relative_to(self.report_dir)) 
                    for folder in self.report_dir.iterdir() 
                    if folder.is_dir()
                ]
            }
            
            summary_path = self.report_dir / "pipeline_summary_enhanced.json"
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, indent=2, ensure_ascii=False)
                
            self.logger.info(f"Enhanced pipeline summary saved to: {summary_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to create pipeline summary: {e}")
            
    def print_enhanced_final_summary(self, execution_results: Dict[str, Dict[str, Any]]):
        """Print enhanced final execution summary."""
        successful_stages = [k for k, v in execution_results.items() if v['success']]
        failed_stages = [k for k, v in execution_results.items() if not v['success']]
        total_time = sum(v['execution_time'] for v in execution_results.values())
        
        if RICH_AVAILABLE:
            console = Console()
            
            # Create results table
            table = Table(title="📊 Pipeline Execution Summary", show_header=True, header_style="bold magenta")
            table.add_column("Stage", style="cyan", width=8)
            table.add_column("Name", style="blue", width=25)
            table.add_column("Status", style="bold", width=12)
            table.add_column("Time", style="yellow", width=10)
            table.add_column("Output", style="green", width=30)
            
            for stage_id, result in execution_results.items():
                status = "✅ Success" if result['success'] else "❌ Failed"
                status_style = "green" if result['success'] else "red"
                
                table.add_row(
                    stage_id,
                    self.stages[stage_id]['name'],
                    status,
                    f"{result['execution_time']:.1f}s",
                    result.get('output_info', 'N/A')
                )
                
            console.print(table)
            
            # Summary panel
            success_rate = (len(successful_stages) / len(execution_results) * 100) if execution_results else 0
            summary_text = f"""
[bold cyan]📊 Pipeline Statistics:[/bold cyan]
• Total Stages: {len(execution_results)}
• Successful: {len(successful_stages)}
• Failed: {len(failed_stages)}
• Success Rate: {success_rate:.1f}%
• Total Execution Time: {total_time:.1f}s
• Clients Processed: {len(self.config_manager.get_clients())}

[bold cyan]📂 Output Location:[/bold cyan]
• Workspace: {self.report_dir}
• Timestamp: {self.pipeline_timestamp}
            """
            
            panel_style = "green" if len(failed_stages) == 0 else "yellow" if len(successful_stages) > 0 else "red"
            console.print(Panel(summary_text, border_style=panel_style))
            
        else:
            print(f"\n{Color.BOLD}📊 PIPELINE EXECUTION SUMMARY{Color.ENDC}")
            print("=" * 80)
            
            for stage_id, result in execution_results.items():
                status = f"{Color.OKGREEN}✅ Success{Color.ENDC}" if result['success'] else f"{Color.FAIL}❌ Failed{Color.ENDC}"
                print(f"Stage {stage_id}: {self.stages[stage_id]['name']} - {status} ({result['execution_time']:.1f}s)")
                
            print("\n" + "=" * 80)
            success_rate = (len(successful_stages) / len(execution_results) * 100) if execution_results else 0
            print(f"📊 Success Rate: {len(successful_stages)}/{len(execution_results)} ({success_rate:.1f}%)")
            print(f"⏱️  Total Time: {total_time:.1f}s")
            print(f"🏢 Clients: {len(self.config_manager.get_clients())}")
            print(f"📂 Output: {self.report_dir}")
            
    def run_enhanced_pipeline(self):
        """Run the enhanced pipeline with full monitoring and reporting."""
        try:
            # Welcome and configuration display
            self.print_enhanced_welcome()
            
            # Show configuration summary
            print(f"\n{Color.CYAN}📋 Current Configuration:{Color.ENDC}")
            self.config_manager.print_config_summary()
            
            # Stage selection
            self.print_enhanced_stage_menu()
            selected_stages = self.get_stage_selection()
            
            # Dependency resolution
            execution_order = self.resolve_dependencies(selected_stages)
            
            print(f"\n{Color.BOLD}📋 Execution Plan:{Color.ENDC}")
            for i, stage_id in enumerate(execution_order, 1):
                stage_name = self.stages[stage_id]['name']
                print(f"  {i}. Stage {stage_id}: {stage_name}")
                
            # Confirmation
            if RICH_AVAILABLE:
                proceed = Confirm.ask(f"\n🚀 Execute {len(execution_order)} stages?", default=True)
            else:
                proceed_input = input(f"\n{Color.CYAN}🚀 Execute {len(execution_order)} stages? (Y/n):{Color.ENDC} ").strip().lower()
                proceed = proceed_input in ['', 'y', 'yes']
                
            if not proceed:
                print(f"{Color.WARNING}⚠️  Pipeline execution cancelled by user.{Color.ENDC}")
                return False
                
            # Execute stages
            execution_results = {}
            overall_success = True
            
            for stage_id in execution_order:
                # Check prerequisites
                if not self.check_stage_prerequisites(stage_id):
                    print(f"{Color.WARNING}⚠️  Skipping stage {stage_id} - prerequisites not met{Color.ENDC}")
                    execution_results[stage_id] = {
                        'success': False,
                        'execution_time': 0,
                        'error': 'Prerequisites not met'
                    }
                    overall_success = False
                    continue
                    
                # Execute stage
                start_time = time.time()
                success = self.execute_stage(stage_id)
                execution_time = time.time() - start_time
                
                execution_results[stage_id] = {
                    'success': success,
                    'execution_time': execution_time,
                    'stage_name': self.stages[stage_id]['name']
                }
                
                if not success:
                    overall_success = False
                    
                    # Ask whether to continue on failure
                    if stage_id != execution_order[-1]:  # Not the last stage
                        if RICH_AVAILABLE:
                            continue_execution = Confirm.ask("❓ Continue with remaining stages?", default=True)
                        else:
                            continue_input = input(f"{Color.CYAN}❓ Continue with remaining stages? (Y/n):{Color.ENDC} ").strip().lower()
                            continue_execution = continue_input in ['', 'y', 'yes']
                            
                        if not continue_execution:
                            print(f"{Color.WARNING}⚠️  Pipeline execution stopped by user.{Color.ENDC}")
                            break
                            
            # Create and display final summary
            self.create_enhanced_pipeline_summary(execution_results)
            self.print_enhanced_final_summary(execution_results)
            
            # Final status
            if overall_success:
                print(f"\n{Color.OKGREEN}🎉 Pipeline completed successfully!{Color.ENDC}")
                return True
            else:
                print(f"\n{Color.WARNING}⚠️  Pipeline completed with some errors.{Color.ENDC}")
                return False
                
        except KeyboardInterrupt:
            print(f"\n{Color.WARNING}⚠️  Pipeline interrupted by user.{Color.ENDC}")
            return False
        except Exception as e:
            print(f"\n{Color.FAIL}💥 Pipeline fatal error: {e}{Color.ENDC}")
            self.logger.error(f"Pipeline fatal error: {e}")
            return False


def main():
    """Enhanced main entry point."""
    try:
        controller = EnhancedPipelineController()
        success = controller.run_enhanced_pipeline()
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