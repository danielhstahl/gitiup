//! Render a `gitiup.toml`: the remote table, the effective store keys and the
//! credential profile each remote resolves to — the shape of
//! `gitiup remote list --json` and `gitiup remote doctor` (giti-xdw.6).
//!
//! Run with `cargo run -p gitiup-host --example remote_show -- [path] [--json]`.

use gitiup_host::{Config, RemoteScheme};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut json = false;
    let mut path = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                eprintln!("usage: remote_show [gitiup.toml] [--json]");
                return Ok(());
            }
            other => path = Some(std::path::PathBuf::from(other)),
        }
    }
    let path = path
        .unwrap_or_else(|| format!("{}/examples/gitiup.toml", env!("CARGO_MANIFEST_DIR")).into());
    let config = match Config::load(&path) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {}", err.message());
            if let Some(hint) = err.hint() {
                eprintln!("hint: {hint}");
            }
            return Err(err.into());
        }
    };
    println!(
        "{} (schema-version {})",
        config.source(),
        config.schema_version
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&config.to_json()?)?);
        return Ok(());
    }

    for remote in config.remotes() {
        println!("\n{}  ({})", remote.name, remote.scheme());
        println!("  url            {}", remote.redacted_url());
        println!("  store prefix   {}", remote.store_prefix);
        println!("  root           {}", remote.root_prefix());
        println!(
            "  timeout        {}",
            gitiup_host::config::format_timeout(remote.timeout)
        );
        for (key, value) in remote.effective_options() {
            println!("  option {key}    {value}");
        }
        println!("  sample object keys (bucket-style hosts)");
        println!("    {}", remote.kv_root());
        println!("    {}", remote.pack_key(&gitiup_host::Oid::zero(32)?));
        if let Some(profile) = config.credential_profile(remote) {
            let declared = profile
                .auth
                .map(|auth| auth.as_str().to_string())
                .unwrap_or_else(|| "not declared".to_string());
            println!(
                "  credentials    profile '{}' declares auth = {declared}",
                remote.credentials_profile.as_deref().unwrap_or_default()
            );
            let resolved = config.credentials_for(remote)?;
            println!(
                "                 resolved: {} -> {resolved:?}",
                resolved.auth.as_str()
            );
        }
        let host_kind = match remote.scheme() {
            RemoteScheme::File => "fs host can serve this remote directly",
            RemoteScheme::S3 => "needs the s3 host (giti-xdw.2)",
            RemoteScheme::Https | RemoteScheme::Ssh => "needs the plain-git host (giti-xdw.3)",
        };
        println!("  host           {host_kind}");
    }

    for warning in config.warnings() {
        println!("\nwarning: {warning}");
    }
    println!(
        "\n(hosts report their capabilities at runtime: `Host::describe` / `Host::capabilities`)"
    );
    Ok(())
}
