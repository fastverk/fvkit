//! `fv-id` — a tiny smoke tool for the fastverk identity flow, calling
//! `fvkit::identity` directly (no daemon). Lets you exercise the real Cognito
//! hosted-UI + PKCE flow end to end:
//!
//!   bazel run //app/identity-cli:fv-id -- login
//!   bazel run //app/identity-cli:fv-id -- whoami
//!   bazel run //app/identity-cli:fv-id -- logout
//!
//! `login` opens the system browser; after you authorize, the token is stored
//! in the keychain and the decoded identity is printed.

fn main() -> anyhow::Result<()> {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    match cmd.as_str() {
        "login" => {
            let id = fvkit::identity::login(|url| {
                println!("Opening your browser to sign in:\n  {url}\n");
                let _ = std::process::Command::new("open").arg(url).spawn();
            })?;
            let name = if id.name.is_empty() { "—" } else { &id.name };
            println!("Signed in as {name} <{}> (sub {})", id.email, id.subject);
        }
        "whoami" => {
            let id = fvkit::identity::whoami()?;
            if id.authenticated {
                println!(
                    "Signed in as {} <{}>; token expires {}",
                    id.name, id.email, id.expires_at
                );
            } else {
                println!("Not signed in.");
            }
        }
        "logout" => {
            let removed = fvkit::identity::logout()?;
            println!("{}", if removed { "Logged out." } else { "Was not signed in." });
        }
        other => {
            eprintln!("usage: fv-id <login|whoami|logout> (got {other:?})");
            std::process::exit(2);
        }
    }
    Ok(())
}
