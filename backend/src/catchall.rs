use check_if_email_exists::{CheckEmailOutput, Reachable};
use tracing::info;
use std::time::Duration;
pub async fn check_catchall(
    email: &str,
    url: &str,
    api_key: &str,
) -> Result<Reachable, anyhow::Error> {
    let client = reqwest::Client::new();
    
    let response = client
    .post(url)
    .header("apitoken", api_key)
    .json(&serde_json::json!({"email": email}))
    .timeout(Duration::from_secs(30)) 
    .send()
    .await?;

    let status = response.status();

    if status == 401 || status == 403 {
        return Err(anyhow::anyhow!("CatchAll auth failed: {}", status));
    }

    if !status.is_success() {
        return Err(anyhow::anyhow!("CatchAll endpoint error: {}", status));
    }

    let json: serde_json::Value = response.json().await?;
info!("CatchAll: raw response -> {}", json);

let score_status = json["result"]["scoreStatus"]
    .as_str()
    .unwrap_or("");

info!("CatchAll: scoreStatus -> '{}'", score_status);

match score_status.to_lowercase().as_str() {
    "deliverable/acceptall" => Ok(Reachable::Safe),
    "undeliverable/acceptall" => Ok(Reachable::Invalid),
    _ => Err(anyhow::anyhow!("Unexpected scoreStatus: {}", score_status)),
}
}

pub async fn apply_catchall(
    output: &mut CheckEmailOutput,
    catchall_url: Option<&str>,
    catchall_api_key: Option<&str>,
) {
    // Condition 1: must be Risky
    if output.is_reachable != Reachable::Risky {
        return;
    }

    // Condition 2: must be is_catch_all = true
    let is_catch_all = match &output.smtp {
        Ok(smtp) => smtp.is_catch_all,
        Err(_) => return,
    };

    if !is_catch_all {
        return;
    }

    // Both url and api_key must be present in payload
    let (url, api_key) = match (catchall_url, catchall_api_key) {
        (Some(u), Some(k)) => (u, k),
        _ => return,
    };
match check_catchall(&output.input, url, api_key).await {
    Ok(new_status) => {
        info!("CatchAll: override applied for {} -> {:?}", &output.input, new_status);
        output.is_reachable = new_status;
    }
    Err(e) => {
        info!("CatchAll: endpoint failed for {} -> reason: {}", &output.input, e);
    }
}
}
