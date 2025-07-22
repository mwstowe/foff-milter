fn main() { 
    let encoded = "=?utf-8?B?44GU5Yip55So5piO57Sw5pu05paw44Gu44GK55+l44KJ44Gb?=";
    let parts: Vec<&str> = encoded.split("?").collect();
    if parts.len() >= 4 && parts[1].to_lowercase() == "utf-8" && parts[2].to_uppercase() == "B" {
        use base64::{Engine as _, engine::general_purpose};
        if let Ok(decoded_bytes) = general_purpose::STANDARD.decode(parts[3]) {
            if let Ok(decoded_string) = String::from_utf8(decoded_bytes) {
                println!("Decoded: {}", decoded_string);
            }
        }
    }
}
