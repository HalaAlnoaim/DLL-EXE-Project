#!/usr/bin/env python3
"""
S-Rank Core - Main Pipeline Controller (Fixed Version)
Improved logic with proper error handling and validation.
"""

import os
import subprocess
import sys
from datetime import datetime
import shutil
import json
from pathlib import Path

# === ANSI Colors
class Color:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    GRAY = "\033[90m"

class SRankPipeline:
    """Main pipeline controller with improved logic."""
    
    def __init__(self):
        self.base_dir = os.getcwd()
        self.pipeline_timestamp = datetime.now().strftime("%Y_%m_%d_%H%M")
        self.report_dir = os.path.join(self.base_dir, f"Reports_{self.pipeline_timestamp}")
        self.temp_dir = os.path.join(self.base_dir, "__temp_output")
        self.errors = []
        
        # Script mapping with validation
        self.script_map = {
            "fetch": os.path.join(self.base_dir, "Data", "Fetch", "fetch.py"),
            "export": os.path.join(self.base_dir, "Exporter", "exporter.py"),
            "analyze": os.path.join(self.base_dir, "GapsAnalyzer", "GapsAnalyzer.py"),
            "scan": os.path.join(self.base_dir, "GapsScanner", "GapsScanner.py")
        }
        
        # Stage dependencies
        self.dependencies = {
            "fetch": [],
            "export": ["fetch"],
            "analyze": ["fetch", "export"],
            "scan": ["fetch", "export", "analyze"]
        }
        
        # Output folder prefixes
        self.folder_prefix_map = {
            "fetch": "Rules_",
            "export": "Exported_Rules_",
            "analyze": "Gap_Analysis_Reports_",
            "scan": "Common_Gaps_"
        }
        
        self.stages_order = ["fetch", "export", "analyze", "scan"]
        
    def print_banner(self):
        """Print the application banner."""
        print(Color.HEADER + r"""

░██████╗​​░░░░░░​​██████╗░░█████╗░███╗░░██╗██╗░░██╗​​░█████╗░░█████╗░██████╗░███████╗
██╔════╝​​░░░░░░​​██╔══██╗██╔══██╗████╗░██║██║░██╔╝​​██╔══██╗██╔══██╗██╔══██╗██╔════╝
╚█████╗░​​█████╗​​██████╔╝███████║██╔██╗██║█████═╝░​​██║░░╚═╝██║░░██║██████╔╝█████╗░░
░╚═══██╗​​╚════╝​​██╔══██╗██╔══██║██║╚████║██╔═██╗░​​██║░░██╗██║░░██║██╔══██╗██╔══╝░░
██████╔╝​​░░░░░░​​██║░░██║██║░░██║██║░╚███║██║░╚██╗​​╚█████╔╝╚█████╔╝██║░░██║███████╗
╚═════╝░​​░░░░░░​​╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░╚══╝╚═╝░░╚═╝​​░╚════╝░░╚════╝░╚═╝░░╚═╝╚══════╝

                    S-Rank Core :: Intelligence Pipeline
""" + Color.ENDC)
        
    def validate_environment(self):
        """Validate that all required scripts and directories exist."""
        missing_scripts = []
        
        for stage, script_path in self.script_map.items():
            if not os.path.exists(script_path):
                missing_scripts.append(f"{stage}: {script_path}")
                
        if missing_scripts:
            print(Color.FAIL + "Missing required scripts:" + Color.ENDC)
            for script in missing_scripts:
                print(f"  - {script}")
            return False
            
        return True
        
    def setup_directories(self):
        """Setup required directories."""
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            os.makedirs(self.temp_dir, exist_ok=True)
            return True
        except Exception as e:
            print(Color.FAIL + f"Failed to create directories: {e}" + Color.ENDC)
            return False
            
    def resolve_dependencies(self, stage_name):
        """Resolve dependencies for a given stage."""
        deps = self.dependencies.get(stage_name, [])
        return deps + [stage_name]
        
    def get_user_choice(self):
        """Get and validate user choice."""
        print(Color.BOLD + "Select an option to run:" + Color.ENDC)
        print("1. Run Stage 1: Fetch Rules         - Collects detection rules from all client clusters (JSON format)")
        print("2. Run Stage 2: Export to Excel     - Converts raw rules to well-formatted Excel files for each client")
        print("3. Run Stage 3: Gap Analyzer        - Analyzes MITRE ATT&CK coverage across all clients")
        print("4. Run Stage 4: Gap Scanner         - Scans coverage reports and generates gap summaries & suggestions")
        print("5. Run Full Pipeline                - Runs all stages in sequence (recommended for full workflow)")
        
        while True:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == "1":
                return ["fetch"], False
            elif choice == "2":
                return self.resolve_dependencies("export"), False
            elif choice == "3":
                return self.resolve_dependencies("analyze"), False
            elif choice == "4":
                return self.resolve_dependencies("scan"), False
            elif choice == "5":
                return self.stages_order, True
            else:
                print(Color.FAIL + "Invalid choice. Please enter a number from 1 to 5." + Color.ENDC)
                
    def run_stage(self, stage, is_final_stage, silent_mode):
        """Run a single stage with proper error handling."""
        script_path = self.script_map[stage]
        current_output_dir = self.report_dir if is_final_stage else self.temp_dir
        
        if not silent_mode or is_final_stage:
            print(Color.OKCYAN + f"\n╔═ Running Stage: {stage.upper()} ═══════════════════════════════" + Color.ENDC)
            print(f"{Color.GRAY}│ Script: {script_path}{Color.ENDC}")
            print(f"{Color.GRAY}│ Output: {current_output_dir}{Color.ENDC}")
            
        try:
            # Create environment variables for the stage
            stage_env = os.environ.copy()
            stage_env.update({
                "SRANK_REPORT_DIR": current_output_dir,
                "SRANK_PIPELINE_TIMESTAMP": self.pipeline_timestamp,
                "SRANK_STAGE": stage.upper(),
                "SRANK_BASE_DIR": self.base_dir
            })
            
            # Run the stage script
            result = subprocess.run(
                [sys.executable, script_path],
                env=stage_env,
                capture_output=silent_mode and not is_final_stage,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode != 0:
                error_msg = f"Stage {stage.upper()} failed with return code {result.returncode}"
                if hasattr(result, 'stderr') and result.stderr:
                    error_msg += f": {result.stderr}"
                raise subprocess.CalledProcessError(result.returncode, script_path, error_msg)
                
            if not silent_mode or is_final_stage:
                print(Color.OKGREEN + f"╚═► Stage {stage.upper()} completed successfully." + Color.ENDC)
                
            return True
            
        except subprocess.TimeoutExpired:
            error_msg = f"Stage {stage.upper()} timed out after 1 hour"
            print(Color.FAIL + f"╚═► {error_msg}" + Color.ENDC)
            self.errors.append(error_msg)
            return False
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Stage {stage.upper()} failed: {e}"
            print(Color.FAIL + f"╚═► {error_msg}" + Color.ENDC)
            self.errors.append(error_msg)
            return False
            
        except Exception as e:
            error_msg = f"Unexpected error in stage {stage.upper()}: {e}"
            print(Color.FAIL + f"╚═► {error_msg}" + Color.ENDC)
            self.errors.append(error_msg)
            return False
            
    def move_stage_outputs(self, stage):
        """Move stage outputs from temp to final directory."""
        prefix = self.folder_prefix_map.get(stage)
        if not prefix:
            return
            
        try:
            for item in os.listdir(self.temp_dir):
                if item.startswith(prefix):
                    src_path = os.path.join(self.temp_dir, item)
                    dst_path = os.path.join(self.report_dir, item)
                    
                    # Handle file conflicts
                    if os.path.exists(dst_path):
                        if os.path.isdir(dst_path):
                            shutil.rmtree(dst_path)
                        else:
                            os.remove(dst_path)
                            
                    shutil.move(src_path, dst_path)
                    
        except Exception as e:
            print(Color.WARNING + f"Warning: Failed to move outputs for stage {stage}: {e}" + Color.ENDC)
            
    def cleanup_intermediate_outputs(self, final_stage, is_full_pipeline):
        """Clean up intermediate outputs if not running full pipeline."""
        if is_full_pipeline:
            return
            
        final_prefix = self.folder_prefix_map.get(final_stage)
        if not final_prefix:
            return
            
        try:
            for item in os.listdir(self.report_dir):
                item_path = os.path.join(self.report_dir, item)
                if os.path.isdir(item_path) and not item.startswith(final_prefix):
                    shutil.rmtree(item_path)
                    
        except Exception as e:
            print(Color.WARNING + f"Warning: Failed to cleanup intermediate outputs: {e}" + Color.ENDC)
            
    def cleanup_temp_directory(self):
        """Clean up temporary directory."""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
        except Exception as e:
            print(Color.WARNING + f"Warning: Failed to cleanup temp directory: {e}" + Color.ENDC)
            
    def create_pipeline_summary(self, selected_stages, is_full_pipeline):
        """Create a summary of the pipeline execution."""
        summary = {
            "pipeline_info": {
                "timestamp": self.pipeline_timestamp,
                "execution_mode": "full_pipeline" if is_full_pipeline else "partial",
                "selected_stages": selected_stages,
                "output_directory": self.report_dir,
                "total_stages": len(selected_stages),
                "errors": len(self.errors)
            },
            "stage_results": {},
            "errors": self.errors
        }
        
        # Add stage-specific information
        for stage in selected_stages:
            summary["stage_results"][stage] = {
                "script_path": self.script_map[stage],
                "completed": stage not in [err.split()[1].lower() for err in self.errors if "Stage" in err]
            }
            
        # Save summary
        summary_path = os.path.join(self.report_dir, "pipeline_summary.json")
        try:
            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=2)
            print(f"{Color.GRAY}Pipeline summary saved to: {summary_path}{Color.ENDC}")
        except Exception as e:
            print(Color.WARNING + f"Warning: Failed to save pipeline summary: {e}" + Color.ENDC)
            
    def run(self):
        """Main execution method."""
        self.print_banner()
        
        # Validate environment
        if not self.validate_environment():
            print(Color.FAIL + "Environment validation failed. Please fix the issues above." + Color.ENDC)
            return 1
            
        # Setup directories
        if not self.setup_directories():
            return 1
            
        # Get user choice
        selected_stages, is_full_pipeline = self.get_user_choice()
        silent_mode = not is_full_pipeline
        
        print(f"{Color.OKBLUE}➤ Output Folder:{Color.ENDC} {self.report_dir}\n")
        
        # Run stages
        final_stage = selected_stages[-1]
        successful_stages = []
        
        for i, stage in enumerate(selected_stages):
            is_final_stage = (stage == final_stage)
            
            # Run the stage
            success = self.run_stage(stage, is_final_stage, silent_mode)
            
            if success:
                successful_stages.append(stage)
                # Move outputs for completed stages
                self.move_stage_outputs(stage)
            else:
                # Stop execution on failure unless it's the full pipeline
                if not is_full_pipeline:
                    print(Color.FAIL + f"Stopping execution due to stage {stage.upper()} failure." + Color.ENDC)
                    break
                    
        # Cleanup intermediate outputs
        self.cleanup_intermediate_outputs(final_stage, is_full_pipeline)
        
        # Create pipeline summary
        self.create_pipeline_summary(selected_stages, is_full_pipeline)
        
        # Final status
        if self.errors:
            print(Color.FAIL + f"\n⚠⚠⚠ Pipeline completed with {len(self.errors)} error(s) ⚠⚠⚠" + Color.ENDC)
            for error in self.errors:
                print(f"  - {error}")
        else:
            print(Color.HEADER + f"\n✔✔✔ Pipeline completed successfully ✔✔✔" + Color.ENDC)
            
        print(f"{Color.OKBLUE}Final report folder:{Color.ENDC} {self.report_dir}")
        print(f"{Color.OKBLUE}Successful stages:{Color.ENDC} {', '.join(successful_stages)}\n")
        
        # Cleanup
        self.cleanup_temp_directory()
        
        return 0 if not self.errors else 1


def main():
    """Entry point."""
    try:
        pipeline = SRankPipeline()
        return pipeline.run()
    except KeyboardInterrupt:
        print(Color.WARNING + "\n\nPipeline interrupted by user." + Color.ENDC)
        return 130
    except Exception as e:
        print(Color.FAIL + f"\nUnexpected error: {e}" + Color.ENDC)
        return 1


if __name__ == "__main__":
    sys.exit(main())