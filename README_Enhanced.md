# 🎯 S-Rank Core Enhanced Pipeline v2.0

## 📋 Overview

S-Rank Core v2.0 is an enhanced modular pipeline system for analyzing security detection coverage against the MITRE ATT&CK framework. This version introduces **ConfigManager integration**, **enhanced technique processing**, and **improved client management**.

### 🆕 What's New in v2.0

- **🔧 ConfigManager Integration**: Centralized configuration management with JSON-based client configuration
- **🏷️ Enhanced Technique Processing**: Support for nested technique.subtechnique.sub_subtechnique formatting
- **📊 Improved Excel Export**: Enhanced formatting with technique analysis sheets
- **🎨 Rich UI Support**: Beautiful console interface with rich library integration
- **⚙️ Flexible Client Management**: Easy addition/removal of clients via configuration
- **🔐 Enhanced Security**: Environment-based credential management with config fallback

## 🏗️ System Architecture

```
S-Rank Core v2.0
├── 📁 config/
│   ├── clients.json          # Client configuration
│   └── credentials.json      # API credentials (optional)
├── 📁 scripts_fixed/
│   ├── config_manager.py     # Configuration management
│   ├── main_updated.py       # Enhanced pipeline controller
│   ├── fetch_updated.py      # Enhanced rule fetcher
│   ├── exporter_updated.py   # Enhanced Excel exporter
│   ├── GapsAnalyzer.py       # Gap analysis (updated to work with new system)
│   └── GapsScanner.py        # Common gaps scanner (updated)
└── requirements.txt          # Dependencies
```

## 🚀 Quick Start

### 1. Installation

```bash
# Clone or download the project
cd s-rank-core

# Install dependencies
pip install -r requirements.txt

# Create configuration (optional - will auto-create)
mkdir -p config
```

### 2. Configuration Setup

#### Option A: Environment Variables (Recommended for CI/CD)
```bash
# API Credentials
export SRANK_API_USERNAME="your_username"
export SRANK_API_PASSWORD="your_password"

# Optional: Custom client list
export SRANK_CLIENTS="cipher,ksf,osh,jda,fa,svc,latis,innova,saip,golfsaudi,new_client"
```

#### Option B: Configuration Files (Recommended for Development)

Create `config/clients.json`:
```json
{
  "clients": [
    {
      "id": "cipher",
      "name": "Cipher Security",
      "enabled": true,
      "priority": 1,
      "description": "Primary security cluster"
    },
    {
      "id": "new_client",
      "name": "New Client Name",
      "enabled": true,
      "priority": 11,
      "description": "Newly added client"
    }
  ],
  "api_settings": {
    "timeout": 30,
    "max_retries": 3,
    "per_page": 100,
    "base_url_template": "https://k{client}.ciphersa.net"
  },
  "processing_settings": {
    "technique_naming_format": "{technique}.{subtechnique}.{sub_subtechnique}",
    "include_disabled_rules": false,
    "excel_sheet_settings": {
      "max_column_width": 100,
      "wrap_text": true,
      "auto_filter": true
    }
  }
}
```

### 3. Run the Pipeline

```bash
# Run the enhanced main script
python scripts_fixed/main_updated.py
```

## 🎛️ Pipeline Stages

| Stage | Name | Description | Dependencies | Output |
|-------|------|-------------|--------------|---------|
| **1** | Fetch Detection Rules | Fetch rules from client APIs with enhanced technique processing | None | `Rules_TIMESTAMP/` |
| **2** | Export to Excel | Convert JSON to enhanced Excel format with technique formatting | Stage 1 | `Exported_Rules_TIMESTAMP/` |
| **3** | Gap Analysis | Analyze MITRE coverage gaps using enhanced technique data | Stage 2 | `Reports_TIMESTAMP/` |
| **4** | Common Gaps Scanner | Identify common gaps across all clients | Stage 3 | `CommonGaps_TIMESTAMP/` |

## 🔧 Configuration Management

### ConfigManager Features

The `ConfigManager` class provides centralized configuration with the following capabilities:

#### Client Management
```python
from config_manager import ConfigManager

config = ConfigManager()

# Get enabled clients
clients = config.get_clients(enabled_only=True)

# Add new client
config.add_client("new_client", "New Client Name", enabled=True, priority=11)

# Update client
config.update_client("cipher", enabled=False)
```

#### Technique Formatting
```python
# Format technique names according to configuration
formatted_name = config.format_technique_name(
    technique="Process Injection",
    subtechnique="Dynamic-link Library Injection",
    sub_subtechnique="Process Hollowing"
)
# Result: "Process Injection.Dynamic-link Library Injection.Process Hollowing"
```

#### API Settings
```python
# Get API configuration
api_settings = config.get_api_settings()
base_url = config.get_base_url_for_client("cipher")
# Result: "https://kcipher.ciphersa.net"
```

## 📊 Enhanced Features

### 1. Technique Processing

The enhanced system now properly handles nested MITRE techniques:

- **Main Techniques**: T1055 (Process Injection)
- **Sub-techniques**: T1055.001 (Dynamic-link Library Injection)  
- **Sub-sub-techniques**: T1055.001.001 (Process Hollowing)

### 2. Excel Export Enhancements

Enhanced Excel files now include:

- **Multiple Sheets**: Rules, Summary, Technique Analysis
- **Enhanced Formatting**: Better column widths, colors, borders
- **Technique Analysis**: Coverage statistics and metrics
- **Auto-filtering**: Built-in Excel filters
- **Rich Metadata**: Processing version, timestamps, client info

### 3. Configuration Validation

The system validates configuration on startup:

```
⚠️  Configuration validation found issues:
  CREDENTIALS:
    - Missing username or password
  CLIENTS:
    - Duplicate client IDs found
```

## 🏢 Client Management

### Adding New Clients

#### Method 1: Configuration File
Edit `config/clients.json` and add:
```json
{
  "id": "aramco",
  "name": "Saudi Aramco",
  "enabled": true,
  "priority": 11,
  "description": "Oil and gas company"
}
```

#### Method 2: Environment Variable
```bash
export SRANK_CLIENTS="cipher,ksf,osh,jda,fa,svc,latis,innova,saip,golfsaudi,aramco"
```

#### Method 3: Programmatically
```python
from config_manager import ConfigManager

config = ConfigManager()
config.add_client("aramco", "Saudi Aramco", enabled=True, priority=11)
```

### Client Configuration Options

- **`id`**: Unique client identifier (used in URLs)
- **`name`**: Display name for reports
- **`enabled`**: Whether to process this client
- **`priority`**: Processing order (lower = earlier)
- **`description`**: Optional client description

## 🔐 Security & Credentials

### Credential Priority (Highest to Lowest)

1. **Environment Variables**
   ```bash
   export SRANK_API_USERNAME="username"
   export SRANK_API_PASSWORD="password"
   ```

2. **Configuration File** (`config/credentials.json`)
   ```json
   {
     "username": "your_username",
     "password": "your_password"
   }
   ```

3. **Interactive Prompt** (if none found)

### Security Best Practices

- Use environment variables in production
- Set restrictive permissions on `config/credentials.json` (600)
- Never commit credentials to version control
- Add `config/credentials.json` to `.gitignore`

## 📈 Output Structure

```
S-Rank_Reports/
└── Pipeline_2024_01_15_1430/
    ├── Rules_2024_01_15_1430/
    │   ├── cipher_rules_15jan2024.json
    │   ├── ksf_rules_15jan2024.json
    │   └── fetch_summary_enhanced.json
    ├── Exported_Rules_2024_01_15_1430/
    │   ├── cipher_enabled_rules_2024_01_15_1430.xlsx
    │   ├── ksf_enabled_rules_2024_01_15_1430.xlsx
    │   └── export_summary_enhanced.json
    ├── Reports_2024_01_15_1430/
    │   ├── cipher_gaps_analysis_2024_01_15_1430.xlsx
    │   └── ksf_gaps_analysis_2024_01_15_1430.xlsx
    ├── CommonGaps_2024_01_15_1430/
    │   └── common_gaps_report_2024_01_15_1430.xlsx
    └── pipeline_summary_enhanced.json
```

## 🎨 Rich UI Features

When `rich` library is installed, enjoy enhanced features:

- **Beautiful Tables**: Stage selection and results
- **Progress Panels**: Configuration summaries
- **Color-coded Status**: Success/failure indicators
- **Interactive Prompts**: Better user experience

Install rich for enhanced UI:
```bash
pip install rich
```

## 🔍 Troubleshooting

### Common Issues

1. **Configuration Validation Errors**
   ```
   Solution: Check config/clients.json syntax and ensure no duplicate IDs
   ```

2. **Missing Credentials**
   ```
   Solution: Set SRANK_API_USERNAME and SRANK_API_PASSWORD environment variables
   ```

3. **Client API Connection Failed**
   ```
   Solution: Verify client ID and API URL template in configuration
   ```

4. **Stage Dependencies Not Met**
   ```
   Solution: Run prerequisite stages first or use "all" to run complete pipeline
   ```

### Debug Mode

Enable debug logging:
```bash
export SRANK_DEBUG=true
export SRANK_LOG_LEVEL=DEBUG
python scripts_fixed/main_updated.py
```

## 🔄 Migration from v1.0

To migrate from the original S-Rank Core:

1. **Update Scripts**: Use the new `*_updated.py` scripts
2. **Create Configuration**: Set up `config/clients.json`
3. **Update Credentials**: Move to environment variables or config file
4. **Test Pipeline**: Run with a single client first

### Backward Compatibility

- Legacy JSON rule files are automatically converted
- Original script functionality is preserved
- Environment variables still work

## 📝 Configuration Examples

### Minimal Configuration
```json
{
  "clients": [
    {"id": "cipher", "name": "Cipher", "enabled": true, "priority": 1}
  ]
}
```

### Advanced Configuration
```json
{
  "clients": [
    {
      "id": "cipher",
      "name": "Cipher Security Solutions",
      "enabled": true,
      "priority": 1,
      "description": "Primary security operations center"
    },
    {
      "id": "test_client",
      "name": "Test Environment",
      "enabled": false,
      "priority": 999,
      "description": "Testing and development"
    }
  ],
  "api_settings": {
    "timeout": 45,
    "max_retries": 5,
    "per_page": 50,
    "base_url_template": "https://k{client}.company.net",
    "headers": {
      "kbn-xsrf": "true",
      "Content-Type": "application/json",
      "User-Agent": "S-Rank-Core/2.0"
    }
  },
  "processing_settings": {
    "technique_naming_format": "{technique}.{subtechnique}.{sub_subtechnique}",
    "include_disabled_rules": false,
    "excel_sheet_settings": {
      "max_column_width": 120,
      "wrap_text": true,
      "auto_filter": true
    }
  },
  "output_settings": {
    "timestamp_format": "%Y_%m_%d_%H%M",
    "create_summary_files": true,
    "archive_old_outputs": true,
    "max_archive_days": 30
  }
}
```

## 🤝 Contributing

When contributing to S-Rank Core v2.0:

1. **Follow Configuration Standards**: Use ConfigManager for all settings
2. **Maintain Backward Compatibility**: Support legacy formats where possible
3. **Update Documentation**: Keep this README current
4. **Test with Multiple Clients**: Ensure functionality across different configurations

## 📄 License

This project is part of the S-Rank Core security analysis toolkit.

---

**🎯 S-Rank Core v2.0 - Enhanced Security Analysis Pipeline**