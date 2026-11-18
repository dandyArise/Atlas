use serde_json::{Value, json};

pub fn lookup(
    client: &reqwest::blocking::Client,
    ip: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let address: std::net::IpAddr = ip.parse()?;
    if !crate::collector::is_public(address) {
        return Err("Adresse non publique : aucune requête envoyée".into());
    }
    let v: Value = client
        .get(format!("https://ipwho.is/{address}"))
        .send()?
        .error_for_status()?
        .json()?;
    if v["success"] != true {
        return Err(v["message"]
            .as_str()
            .unwrap_or("Localisation indisponible")
            .into());
    }
    let lat = v["latitude"]
        .as_f64()
        .filter(|x| x.is_finite() && (-90.0..=90.0).contains(x))
        .ok_or("Latitude invalide")?;
    let lon = v["longitude"]
        .as_f64()
        .filter(|x| x.is_finite() && (-180.0..=180.0).contains(x))
        .ok_or("Longitude invalide")?;
    Ok(
        json!({"lat":lat,"lon":lon,"country":v["country"],"city":v["city"],"org":v["connection"]["org"]}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_ip_never_needs_network() {
        let client = reqwest::blocking::Client::new();
        assert!(
            lookup(&client, "127.0.0.1")
                .unwrap_err()
                .to_string()
                .contains("non publique")
        );
    }
    #[test]
    #[ignore = "Live provider check using only the public reference IP 1.1.1.1"]
    fn live_reference_ip() {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let result = lookup(&client, "1.1.1.1").unwrap();
        assert!(result["country"].is_string());
        assert!(result["lat"].as_f64().is_some());
        assert!(result["lon"].as_f64().is_some());
    }
}
