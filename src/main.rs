use clap::Parser;
use reqwest::blocking::Client;
use reqwest::header::{HeaderValue, LOCATION, SET_COOKIE};
use scraper::{ElementRef, Html, Selector};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use url::Url;

#[derive(Debug, Parser)]
#[command(name = "kc-cookie-dump")]
#[command(about = "Dump selected cookies after authenticating via Keycloak", long_about = None)]
struct Args {
    /// The initial URL of the service which triggers the Keycloak redirect
    #[arg(long)]
    url: String,

    /// Cookie name to dump. May be specified multiple times.
    #[arg(long = "cookie", required = true)]
    cookies: Vec<String>,

    /// Output directory for per-cookie files written by --dump-cookies.
    #[arg(long, default_value = ".")]
    out_dir: PathBuf,

    /// Also write one raw Set-Cookie file per requested cookie name.
    #[arg(long, default_value_t = false)]
    dump_cookies: bool,

    /// Maximum number of redirects to follow (for safety)
    #[arg(long, default_value_t = 30)]
    max_redirects: usize,
}

#[derive(Debug)]
struct LoginForm {
    action: Url,
    username_name: String,
    password_name: String,
    fields: Vec<(String, String)>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.cookies.is_empty() {
        return Err("at least one --cookie must be provided".into());
    }

    std::fs::create_dir_all(&args.out_dir)?;

    let client = Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .tls_danger_accept_invalid_certs(true)
        .user_agent("kc-cookie-dump/0.1.0")
        .build()?;

    let start_url = Url::parse(&args.url)?;

    let mut set_cookie_headers: Vec<String> = Vec::new();

    // 1) Call service URL and follow redirects until we reach the Keycloak login page.
    let (login_page_url, login_page_html) = follow_until_login_page(
        &client,
        start_url.clone(),
        args.max_redirects,
        &mut set_cookie_headers,
    )?;

    // 2) Parse login form (username/password fields + action URL)
    let mut login_form = parse_login_form(&login_page_url, &login_page_html)?;

    // 3) Prompt user for credentials
    let username = prompt("Username: ")?;
    let password = rpassword::prompt_password("Password: ")?;

    set_form_field(&mut login_form.fields, &login_form.username_name, username);
    set_form_field(&mut login_form.fields, &login_form.password_name, password);

    // 4) Submit login form
    let mut resp = client
        .post(login_form.action.clone())
        .form(&login_form.fields)
        .send()?;

    collect_set_cookie_headers(&resp, &mut set_cookie_headers)?;

    // 5) Follow redirects back to service; this should mint desired cookies.
    for _ in 0..args.max_redirects {
        if resp.status().is_redirection() {
            let next = redirect_target(resp.url(), resp.headers().get(LOCATION))?;
            resp = client.get(next).send()?;
            collect_set_cookie_headers(&resp, &mut set_cookie_headers)?;
            continue;
        }
        break;
    }

    // 6) Filter and dump last Set-Cookie per requested name
    let wanted: HashSet<&str> = args.cookies.iter().map(|s| &**s).collect();
    let mut last_per_cookie: HashMap<String, String> = HashMap::new();

    for hdr in set_cookie_headers {
        let Some((name, _rest)) = hdr.split_once('=') else {
            continue;
        };

        if wanted.contains(name) {
            last_per_cookie.insert(name.to_string(), hdr);
        }
    }

    // Ensure all requested cookies were found.
    let mut missing: Vec<&str> = Vec::new();
    for name in &args.cookies {
        if !last_per_cookie.contains_key(name) {
            missing.push(&**name);
        }
    }

    if !missing.is_empty() {
        return Err(format!(
            "missing cookies in Set-Cookie headers: {}",
            missing.join(", ")
        )
        .into());
    }

    if args.dump_cookies {
        for name in &args.cookies {
            let value = &last_per_cookie[name];
            let path = cookie_output_path(&args.out_dir, name);
            std::fs::write(&path, value)?;
            eprintln!("wrote {name} -> {}", path.display());
        }
    }

    let cookie_jar_path = args.out_dir.join("cookies.jar");
    let default_domain = start_url.host_str().unwrap_or("localhost");
    let mut lines = Vec::new();
    lines.push("# Netscape HTTP Cookie File".to_string());
    for name in &args.cookies {
        let raw = &last_per_cookie[name];
        lines.push(cookie_jar_line(raw, default_domain));
    }
    let content = lines.join("\n") + "\n";
    std::fs::write(&cookie_jar_path, &content)?;
    eprintln!("wrote cookie jar -> {}", cookie_jar_path.display());

    Ok(())
}

fn cookie_output_path(out_dir: &Path, name: &str) -> PathBuf {
    out_dir.join(format!("{name}.set-cookie"))
}

/// Convert a raw `Set-Cookie` header value into a Netscape cookie-jar line.
///
/// Format: domain \t include_subdomains \t path \t secure \t expiry \t name \t value
fn cookie_jar_line(raw: &str, default_domain: &str) -> String {
    // Split "name=value; attr1; attr2=val" into name-value and attributes.
    let (name_value, attrs_str) = raw.split_once(';').unwrap_or((raw, ""));

    let (name, value) = name_value.split_once('=').unwrap_or((name_value, ""));
    let name = name.trim();
    let value = value.trim();

    let mut domain: Option<String> = None;
    let mut path = "/".to_string();
    let mut secure = false;
    let mut expiry: u64 = 0; // 0 = session cookie

    for attr in attrs_str.split(';') {
        let attr = attr.trim();
        if attr.is_empty() {
            continue;
        }
        let lower = attr.to_ascii_lowercase();
        if lower == "secure" {
            secure = true;
        } else if lower == "httponly" {
            // not relevant for cookie jar format
        } else if let Some((key, val)) = attr.split_once('=') {
            let key = key.trim().to_ascii_lowercase();
            let val = val.trim();
            match key.as_str() {
                "domain" => {
                    domain = Some(val.to_string());
                }
                "path" => {
                    path = val.to_string();
                }
                "max-age" => {
                    if let Ok(secs) = val.parse::<u64>() {
                        expiry = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                            + secs;
                    }
                }
                _ => {}
            }
        }
    }

    let domain = domain.unwrap_or_else(|| default_domain.to_string());
    // If domain starts with '.', subdomains are included.
    let include_subdomains = domain.starts_with('.');

    format!(
        "{domain}\t{sub}\t{path}\t{sec}\t{expiry}\t{name}\t{value}",
        sub = if include_subdomains { "TRUE" } else { "FALSE" },
        sec = if secure { "TRUE" } else { "FALSE" },
    )
}

fn prompt(msg: &str) -> Result<String, Box<dyn Error>> {
    let mut stdout = io::stdout();
    write!(stdout, "{msg}")?;
    stdout.flush()?;

    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim_end().to_string())
}

fn set_form_field(fields: &mut Vec<(String, String)>, name: &str, value: String) {
    for (k, v) in fields.iter_mut() {
        if k == name {
            *v = value;
            return;
        }
    }
    fields.push((name.to_string(), value));
}

fn follow_until_login_page(
    client: &Client,
    start_url: Url,
    max_redirects: usize,
    set_cookie_headers: &mut Vec<String>,
) -> Result<(Url, String), Box<dyn Error>> {
    let mut url = start_url;

    for _ in 0..max_redirects {
        let resp = client.get(url.clone()).send()?;
        collect_set_cookie_headers(&resp, set_cookie_headers)?;

        if resp.status().is_redirection() {
            url = redirect_target(resp.url(), resp.headers().get(LOCATION))?;
            continue;
        }

        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if content_type.contains("text/html") {
            let page_url = resp.url().clone();
            let body = resp.text()?;
            // Only accept it as login page if we can find a login form in it.
            if parse_login_form(&page_url, &body).is_ok() {
                return Ok((page_url, body));
            }

            return Err("received HTML page but could not find Keycloak login form".into());
        }

        return Err(format!(
            "expected redirect or HTML login page, got status {} with content-type '{content_type}'",
            resp.status()
        )
        .into());
    }

    Err("too many redirects while trying to reach login page".into())
}

fn collect_set_cookie_headers(
    resp: &reqwest::blocking::Response,
    sink: &mut Vec<String>,
) -> Result<(), Box<dyn Error>> {
    for value in resp.headers().get_all(SET_COOKIE).iter() {
        sink.push(header_value_to_string(value)?);
    }
    Ok(())
}

fn header_value_to_string(value: &HeaderValue) -> Result<String, Box<dyn Error>> {
    Ok(value.to_str()?.to_string())
}

fn redirect_target(base: &Url, location: Option<&HeaderValue>) -> Result<Url, Box<dyn Error>> {
    let location = location.ok_or("redirect response missing Location header")?;
    let location = location.to_str()?;

    // `join` works for both relative and absolute URLs.
    Ok(base.join(location)?)
}

fn parse_login_form(page_url: &Url, html: &str) -> Result<LoginForm, Box<dyn Error>> {
    let document = Html::parse_document(html);

    let form_sel = Selector::parse("form").unwrap();
    let input_sel = Selector::parse("input").unwrap();

    for form in document.select(&form_sel) {
        if !form_contains_password_input(&form, &input_sel) {
            continue;
        }

        let action = form.value().attr("action").unwrap_or("").trim().to_string();

        let action_url = if action.is_empty() {
            page_url.clone()
        } else {
            page_url.join(&action)?
        };

        let mut fields: Vec<(String, String)> = Vec::new();
        let mut password_name: Option<String> = None;
        let mut text_candidates: Vec<String> = Vec::new();

        for input in form.select(&input_sel) {
            let Some(name) = input.value().attr("name") else {
                continue;
            };
            let ty = input
                .value()
                .attr("type")
                .unwrap_or("text")
                .trim()
                .to_ascii_lowercase();

            let value = input.value().attr("value").unwrap_or("");
            fields.push((name.to_string(), value.to_string()));

            if ty == "password" {
                password_name = Some(name.to_string());
            } else if ty != "hidden" {
                // Candidate for username field.
                text_candidates.push(name.to_string());
            }
        }

        let password_name = password_name.ok_or("login form did not have a password input")?;
        let username_name = choose_username_field(&text_candidates)?;

        return Ok(LoginForm {
            action: action_url,
            username_name,
            password_name,
            fields,
        });
    }

    Err("could not find a login form with a password input".into())
}

fn form_contains_password_input(form: &ElementRef<'_>, input_sel: &Selector) -> bool {
    for input in form.select(input_sel) {
        let ty = input
            .value()
            .attr("type")
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if ty == "password" {
            return true;
        }
    }
    false
}

fn choose_username_field(candidates: &[String]) -> Result<String, Box<dyn Error>> {
    if candidates.is_empty() {
        return Err("login form had no non-hidden input candidates for username".into());
    }

    // Prefer common names.
    for preferred in ["username", "email"] {
        if let Some(name) = candidates
            .iter()
            .find(|n| n.eq_ignore_ascii_case(preferred))
        {
            return Ok(name.to_string());
        }
    }

    // Then try substring match.
    if let Some(name) = candidates
        .iter()
        .find(|n| n.to_ascii_lowercase().contains("user"))
    {
        return Ok(name.to_string());
    }

    if let Some(name) = candidates
        .iter()
        .find(|n| n.to_ascii_lowercase().contains("mail"))
    {
        return Ok(name.to_string());
    }

    // Fallback: first non-hidden, non-password input.
    Ok(candidates[0].to_string())
}
