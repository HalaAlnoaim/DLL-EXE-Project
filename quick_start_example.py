#!/usr/bin/env python3
"""
S-Rank Core v2.0 - Quick Start Example
This script demonstrates how to use the enhanced S-Rank Core system.
"""

import os
import sys
from pathlib import Path
import json

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.append(str(project_root / "scripts_fixed"))

from config_manager import ConfigManager

def setup_example_environment():
    """Setup example environment for testing."""
    print("🚀 Setting up S-Rank Core v2.0 Example Environment")
    print("=" * 60)
    
    # Create config directory
    config_dir = project_root / "config"
    config_dir.mkdir(exist_ok=True)
    
    # Setup example credentials (you should replace these)
    print("\n1. 🔐 Setting up credentials...")
    
    # Option 1: Environment variables (recommended)
    print("   Setting environment variables for this session...")
    os.environ["SRANK_API_USERNAME"] = "your_username_here"
    os.environ["SRANK_API_PASSWORD"] = "your_password_here"
    
    # Option 2: Configuration file (alternative)
    creds_file = config_dir / "credentials.json"
    if not creds_file.exists():
        print("   Creating example credentials file...")
        example_creds = {
            "username": "your_username_here",
            "password": "your_password_here",
            "created": "example_setup"
        }
        with open(creds_file, 'w') as f:
            json.dump(example_creds, f, indent=2)
        print(f"   📄 Created: {creds_file}")
        print("   ⚠️  Remember to update with your actual credentials!")

def demonstrate_config_manager():
    """Demonstrate ConfigManager capabilities."""
    print("\n2. ⚙️  Demonstrating ConfigManager...")
    
    # Initialize ConfigManager
    config = ConfigManager()
    
    # Display current configuration
    print("   📋 Current Configuration:")
    config.print_config_summary()
    
    # Show how to get client information
    print("\n   🏢 Client Management Examples:")
    clients = config.get_clients()
    print(f"   • Total enabled clients: {len(clients)}")
    
    for client in clients[:3]:  # Show first 3
        print(f"   • {client['id']}: {client['name']} (Priority: {client['priority']})")
        
    # Show technique formatting
    print("\n   🏷️  Technique Formatting Example:")
    formatted = config.format_technique_name(
        technique="Process Injection",
        subtechnique="Dynamic-link Library Injection",
        sub_subtechnique="Process Hollowing"
    )
    print(f"   • Format: {config.get_technique_naming_format()}")
    print(f"   • Result: {formatted}")
    
    # Show API settings
    print("\n   🔗 API Configuration:")
    api_settings = config.get_api_settings()
    print(f"   • Timeout: {api_settings.get('timeout')}s")
    print(f"   • Max Retries: {api_settings.get('max_retries')}")
    print(f"   • Per Page: {api_settings.get('per_page')}")
    
    # Example of adding a new client
    print("\n   ➕ Adding Example Client:")
    success = config.add_client(
        client_id="example_client",
        name="Example Organization",
        enabled=True,
        priority=99
    )
    if success:
        print("   ✅ Example client added successfully!")
        
        # Show updated client list
        updated_clients = config.get_clients()
        print(f"   📊 Updated client count: {len(updated_clients)}")
    else:
        print("   ⚠️  Client may already exist")

def show_pipeline_usage():
    """Show how to use the enhanced pipeline."""
    print("\n3. 🎯 Pipeline Usage Examples:")
    
    print("   📋 Available Scripts:")
    scripts_dir = project_root / "scripts_fixed"
    
    scripts = [
        ("main_updated.py", "Enhanced pipeline controller with ConfigManager"),
        ("fetch_updated.py", "Enhanced rule fetcher with technique processing"),
        ("exporter_updated.py", "Enhanced Excel exporter with formatting"),
        ("config_manager.py", "Configuration management system")
    ]
    
    for script_name, description in scripts:
        script_path = scripts_dir / script_name
        exists = "✅" if script_path.exists() else "❌"
        print(f"   {exists} {script_name:<20} - {description}")
    
    print("\n   🚀 How to run the pipeline:")
    print("   1. Set your credentials:")
    print("      export SRANK_API_USERNAME='your_username'")
    print("      export SRANK_API_PASSWORD='your_password'")
    print()
    print("   2. Run the enhanced pipeline:")
    print("      python scripts_fixed/main_updated.py")
    print()
    print("   3. Or run individual stages:")
    print("      python scripts_fixed/fetch_updated.py      # Stage 1: Fetch rules")
    print("      python scripts_fixed/exporter_updated.py   # Stage 2: Export to Excel")

def show_configuration_examples():
    """Show configuration file examples."""
    print("\n4. 📝 Configuration Examples:")
    
    # Minimal configuration
    minimal_config = {
        "clients": [
            {"id": "cipher", "name": "Cipher Security", "enabled": True, "priority": 1},
            {"id": "test_client", "name": "Test Client", "enabled": False, "priority": 99}
        ],
        "api_settings": {
            "timeout": 30,
            "max_retries": 3,
            "per_page": 100
        }
    }
    
    print("   📄 Minimal Configuration Example (config/clients.json):")
    print(json.dumps(minimal_config, indent=2))
    
    # Show how to add new clients
    print("\n   ➕ Adding New Clients:")
    print("   Method 1 - Edit config/clients.json:")
    new_client_example = {
        "id": "new_company",
        "name": "New Company Ltd",
        "enabled": True,
        "priority": 11,
        "description": "Newly onboarded client"
    }
    print(json.dumps(new_client_example, indent=2))
    
    print("\n   Method 2 - Environment Variable:")
    print("   export SRANK_CLIENTS='cipher,ksf,osh,new_company'")

def show_enhanced_features():
    """Show enhanced features of v2.0."""
    print("\n5. ✨ Enhanced Features in v2.0:")
    
    features = [
        ("🔧 ConfigManager", "Centralized configuration management"),
        ("🏷️  Enhanced Techniques", "Support for technique.subtechnique.sub_subtechnique"),
        ("📊 Better Excel Export", "Multiple sheets, analysis, formatting"),
        ("🎨 Rich UI", "Beautiful console interface (install: pip install rich)"),
        ("⚙️  Flexible Clients", "Easy addition/removal of clients"),
        ("🔐 Enhanced Security", "Environment-based credential management"),
        ("📋 Better Logging", "Improved error handling and debugging"),
        ("🔄 Backward Compatible", "Works with existing JSON files")
    ]
    
    for feature, description in features:
        print(f"   {feature:<20} - {description}")

def show_troubleshooting():
    """Show common troubleshooting steps."""
    print("\n6. 🔍 Troubleshooting:")
    
    issues = [
        ("Missing credentials", "Set SRANK_API_USERNAME and SRANK_API_PASSWORD"),
        ("Config validation errors", "Check config/clients.json syntax"),
        ("Client connection failed", "Verify client ID and API URL"),
        ("Import errors", "Run: pip install -r requirements.txt"),
        ("Permission denied", "Check file permissions on config files")
    ]
    
    for issue, solution in issues:
        print(f"   ❓ {issue:<25} → {solution}")
    
    print("\n   🐛 Debug Mode:")
    print("   export SRANK_DEBUG=true")
    print("   export SRANK_LOG_LEVEL=DEBUG")
    print("   python scripts_fixed/main_updated.py")

def main():
    """Main demonstration function."""
    try:
        print("🎯 S-Rank Core v2.0 - Quick Start Example")
        print("This script demonstrates the enhanced features and capabilities.")
        print("=" * 80)
        
        # Setup example environment
        setup_example_environment()
        
        # Demonstrate ConfigManager
        demonstrate_config_manager()
        
        # Show pipeline usage
        show_pipeline_usage()
        
        # Show configuration examples
        show_configuration_examples()
        
        # Show enhanced features
        show_enhanced_features()
        
        # Show troubleshooting
        show_troubleshooting()
        
        print("\n" + "=" * 80)
        print("🎉 Quick Start Example Complete!")
        print()
        print("📚 Next Steps:")
        print("1. Update your credentials in config/credentials.json or environment variables")
        print("2. Customize client configuration in config/clients.json")
        print("3. Run the pipeline: python scripts_fixed/main_updated.py")
        print("4. Check the README_Enhanced.md for detailed documentation")
        print()
        print("🔗 For support or questions, refer to the documentation.")
        
    except Exception as e:
        print(f"❌ Error during demonstration: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())