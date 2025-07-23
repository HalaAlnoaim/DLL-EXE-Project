"""
Folder management utility for S-Rank Core system.
Handles directory creation, organization, and cleanup.
"""

import os
import shutil
from datetime import datetime
from pathlib import Path


class FolderManager:
    """Manages folder structure and organization for S-Rank Core outputs."""
    
    def __init__(self, base_output_dir):
        """
        Initialize folder manager.
        
        Args:
            base_output_dir (str): Base directory for all outputs
        """
        self.base_output_dir = base_output_dir
        self.folder_structure = {
            "01_client_rules": "Raw JSON detection rules from clients",
            "02_excel_exports": "Excel exports of enabled rules",
            "03_gap_analysis": "Individual client gap analysis reports",
            "04_master_reports": "Combined analysis and recommendations",
            "logs": "System logs and execution records",
            "temp": "Temporary files (auto-cleaned)"
        }
        
    def create_output_structure(self):
        """Create the complete output directory structure."""
        # Create base directory
        os.makedirs(self.base_output_dir, exist_ok=True)
        
        # Create all subdirectories
        for folder_name, description in self.folder_structure.items():
            folder_path = os.path.join(self.base_output_dir, folder_name)
            os.makedirs(folder_path, exist_ok=True)
            
            # Create a README file in each folder
            readme_path = os.path.join(folder_path, "README.txt")
            if not os.path.exists(readme_path):
                with open(readme_path, 'w') as f:
                    f.write(f"S-Rank Core - {folder_name}\n")
                    f.write("=" * 40 + "\n")
                    f.write(f"Description: {description}\n")
                    f.write(f"Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    
        return self.base_output_dir
        
    def get_stage_folder(self, stage_number, create=True):
        """
        Get the folder path for a specific stage.
        
        Args:
            stage_number (int): Stage number (1-4)
            create (bool): Whether to create the folder if it doesn't exist
            
        Returns:
            str: Folder path for the stage
        """
        stage_folders = {
            1: "01_client_rules",
            2: "02_excel_exports", 
            3: "03_gap_analysis",
            4: "04_master_reports"
        }
        
        if stage_number not in stage_folders:
            raise ValueError(f"Invalid stage number: {stage_number}")
            
        folder_path = os.path.join(self.base_output_dir, stage_folders[stage_number])
        
        if create:
            os.makedirs(folder_path, exist_ok=True)
            
        return folder_path
        
    def get_temp_folder(self, subfolder=None):
        """
        Get a temporary folder path.
        
        Args:
            subfolder (str, optional): Subfolder name within temp
            
        Returns:
            str: Temporary folder path
        """
        temp_path = os.path.join(self.base_output_dir, "temp")
        
        if subfolder:
            temp_path = os.path.join(temp_path, subfolder)
            
        os.makedirs(temp_path, exist_ok=True)
        return temp_path
        
    def cleanup_temp_files(self):
        """Remove all temporary files and folders."""
        temp_path = os.path.join(self.base_output_dir, "temp")
        
        if os.path.exists(temp_path):
            shutil.rmtree(temp_path)
            os.makedirs(temp_path, exist_ok=True)
            
    def archive_run(self, archive_dir="archived_runs"):
        """
        Archive the current run to a separate directory.
        
        Args:
            archive_dir (str): Directory to store archived runs
            
        Returns:
            str: Path to archived directory
        """
        # Create archive directory
        os.makedirs(archive_dir, exist_ok=True)
        
        # Generate archive name
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_name = f"srank_run_{timestamp}"
        archive_path = os.path.join(archive_dir, archive_name)
        
        # Copy current run to archive
        shutil.copytree(self.base_output_dir, archive_path)
        
        return archive_path
        
    def get_latest_file(self, folder_path, pattern="*"):
        """
        Get the most recently created file in a folder.
        
        Args:
            folder_path (str): Path to search in
            pattern (str): File pattern to match
            
        Returns:
            str or None: Path to latest file, or None if no files found
        """
        if not os.path.exists(folder_path):
            return None
            
        files = list(Path(folder_path).glob(pattern))
        
        if not files:
            return None
            
        # Sort by modification time, return most recent
        latest_file = max(files, key=os.path.getmtime)
        return str(latest_file)
        
    def list_client_files(self, stage_folder):
        """
        List all client files in a stage folder.
        
        Args:
            stage_folder (str): Path to stage folder
            
        Returns:
            list: List of client file paths
        """
        if not os.path.exists(stage_folder):
            return []
            
        files = []
        for item in os.listdir(stage_folder):
            item_path = os.path.join(stage_folder, item)
            if os.path.isfile(item_path) and not item.startswith('.') and item != "README.txt":
                files.append(item_path)
                
        return sorted(files)
        
    def get_summary_info(self):
        """
        Get summary information about the current run.
        
        Returns:
            dict: Summary information
        """
        summary = {
            "base_directory": self.base_output_dir,
            "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stages": {}
        }
        
        for stage_num in range(1, 5):
            try:
                stage_folder = self.get_stage_folder(stage_num, create=False)
                if os.path.exists(stage_folder):
                    files = self.list_client_files(stage_folder)
                    summary["stages"][f"stage_{stage_num}"] = {
                        "folder": stage_folder,
                        "file_count": len(files),
                        "files": [os.path.basename(f) for f in files]
                    }
            except:
                continue
                
        return summary