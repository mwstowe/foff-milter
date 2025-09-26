#!/usr/bin/env python3
"""
Simple YAML merger for foff-milter configuration files
Merges whitelist.yaml and rules-base.yaml into hotel.yaml
"""

import yaml
import sys

def merge_yaml_files(whitelist_file, base_file, output_file):
    """Merge whitelist and base rules into a single configuration"""
    
    # Load whitelist configuration
    with open(whitelist_file, 'r') as f:
        whitelist_config = yaml.safe_load(f)
    
    # Load base rules configuration  
    with open(base_file, 'r') as f:
        base_config = yaml.safe_load(f)
    
    # Start with whitelist config (has socket_path, statistics, etc.)
    merged_config = whitelist_config.copy()
    
    # Append base rules to whitelist rules
    if 'rules' in base_config:
        merged_config['rules'].extend(base_config['rules'])
    
    # Write merged configuration
    with open(output_file, 'w') as f:
        yaml.dump(merged_config, f, default_flow_style=False, sort_keys=False)
    
    print(f"✅ Successfully merged {whitelist_file} and {base_file} into {output_file}")
    print(f"📊 Total rules: {len(merged_config['rules'])}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 merge-yaml.py whitelist.yaml rules-base.yaml hotel.yaml")
        sys.exit(1)
    
    whitelist_file, base_file, output_file = sys.argv[1:4]
    
    try:
        merge_yaml_files(whitelist_file, base_file, output_file)
    except Exception as e:
        print(f"❌ Error merging files: {e}")
        sys.exit(1)
