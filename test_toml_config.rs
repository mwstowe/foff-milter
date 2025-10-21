use foff_milter::toml_config::TomlConfig;

fn main() -> anyhow::Result<()> {
    println!("🧪 Testing TOML Configuration Loading");
    
    // Load TOML config
    let toml_config = TomlConfig::load_from_file("test-toml.toml")?;
    println!("✅ TOML config loaded successfully");
    println!("   Socket: {}", toml_config.system.socket_path);
    println!("   Version: {}", toml_config.system.version);
    
    if let Some(modules) = &toml_config.modules {
        println!("   Modules enabled: {}", modules.enabled);
        println!("   Module dir: {}", modules.config_dir);
    }
    
    // Convert to legacy config
    let legacy_config = toml_config.to_legacy_config()?;
    println!("✅ Converted to legacy config successfully");
    println!("   Socket: {}", legacy_config.socket_path);
    println!("   Module dir: {:?}", legacy_config.module_config_dir);
    println!("   Default action: {:?}", legacy_config.default_action);
    
    Ok(())
}
