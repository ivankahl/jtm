//! The Windows system proxy (SPEC.md section 13).
//!
//! WinINET keeps the per-user proxy under `HKCU\Software\Microsoft\Windows\CurrentVersion\
//! Internet Settings`, which any user can read; nothing here needs elevation. [`read`] is the
//! only function that touches the registry. Interpreting the values is plain string handling in
//! [`WinInetSettings::interpret`], so it is tested on every platform.
//!
//! PAC files are not supported: a configured script is reported, never fetched or run.

// SPEC-QUESTION: section 13 says "WinINET or WinHTTP". Only the per-user WinINET settings under
// HKCU are read; the machine-wide WinHTTP blob lives under HKLM and is a binary format. Most
// corporate machines mirror one into the other, so this covers the common case.
// SPEC-QUESTION: the `<local>` bypass (every dotless host name) cannot be expressed in
// `NO_PROXY` syntax, so it is narrowed to loopback and traffic to intranet names goes through
// the proxy. The proxy is the more cautious route; the note in `SystemProxy` says so.

/// The raw WinINET values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WinInetSettings {
    /// `ProxyEnable`.
    pub enabled: bool,
    /// `ProxyServer`: `host:port`, or `http=host:port;https=host:port;ftp=...;socks=...`.
    pub proxy_server: Option<String>,
    /// `ProxyOverride`: `;`-separated hosts that bypass the proxy, such as
    /// `localhost;*.corp;10.*;<local>`.
    pub proxy_override: Option<String>,
    /// `AutoConfigURL`, the PAC script.
    pub auto_config_url: Option<String>,
}

/// The system proxy in the terms of `HTTP_PROXY` and `NO_PROXY`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemProxy {
    /// The proxy for `http` URLs, as written in the settings; it may lack a scheme.
    pub http: Option<String>,
    /// The proxy for `https` URLs.
    pub https: Option<String>,
    /// The bypass list in `NO_PROXY` syntax.
    pub bypass: Option<String>,
    /// Settings jtm cannot honour, for `jtm doctor`.
    pub notes: Vec<String>,
}

impl WinInetSettings {
    /// Turns the registry values into the proxy for each scheme and a `NO_PROXY` list.
    pub fn interpret(&self) -> SystemProxy {
        let mut system = SystemProxy::default();
        if let Some(url) = non_empty(self.auto_config_url.as_deref()) {
            system.notes.push(format!(
                "Windows is configured with a PAC file ({}), which jtm does not support; \
                 set `network.proxy` to use a proxy",
                // The URL may hold credentials, and notes are printed by `jtm doctor`.
                super::redact_url(url)
            ));
        }
        let servers = non_empty(self.proxy_server.as_deref());
        if !self.enabled || servers.is_none() {
            // The bypass list means nothing without a proxy, and no static proxy leaves
            // only the PAC note.
            return system;
        }
        let (http, https) = split_servers(servers.unwrap_or_default());
        system.http = http;
        system.https = https;
        if system.http.is_none() && system.https.is_none() {
            // Only `ftp=` or `socks=` entries: requests connect directly, which the person
            // should be told rather than left to find out.
            system.notes.push(
                "the Windows proxy settings name no proxy for http or https, so jtm connects \
                 directly; set `network.proxy` to use a proxy"
                    .to_owned(),
            );
            return system;
        }
        let (bypass, notes) = convert_bypass(self.proxy_override.as_deref().unwrap_or_default());
        system.bypass = bypass;
        system.notes.extend(notes);
        system
    }
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

/// Splits `ProxyServer` into the proxies for `http` and `https`. An entry for a scheme beats
/// a bare `host:port`, which serves any scheme without one. `ftp=` and `socks=` entries are
/// not used.
fn split_servers(servers: &str) -> (Option<String>, Option<String>) {
    let (mut http, mut https, mut bare) = (None, None, None);
    for entry in servers.split(|c: char| c == ';' || c.is_whitespace()) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.split_once('=') {
            Some((protocol, address)) => match protocol.trim().to_ascii_lowercase().as_str() {
                "http" => http = Some(address.trim().to_owned()),
                "https" => https = Some(address.trim().to_owned()),
                _ => {}
            },
            None => bare = bare.or_else(|| Some(entry.to_owned())),
        }
    }
    (http.or_else(|| bare.clone()), https.or(bare))
}

/// Converts `ProxyOverride` into `NO_PROXY` syntax, plus notes on what could not be carried
/// over. A bypass jtm cannot express sends that traffic through the proxy, which is the safe
/// way to fail.
fn convert_bypass(list: &str) -> (Option<String>, Vec<String>) {
    let mut entries: Vec<String> = Vec::new();
    let mut notes = Vec::new();
    for entry in list.split([';', ',']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        if entry.eq_ignore_ascii_case("<local>") {
            // `<local>` means every name without a dot, which `NO_PROXY` cannot say.
            entries.extend(["localhost", "127.0.0.1", "::1"].map(str::to_owned));
            notes.push(
                "the Windows bypass entry `<local>` is applied to loopback addresses only"
                    .to_owned(),
            );
        } else if !entry.contains('*') {
            entries.push(entry.to_owned());
        } else if entry == "*" {
            entries.push("*".to_owned());
        } else if let Some(domain) = entry.strip_prefix("*.").filter(|d| !d.contains('*')) {
            entries.push(format!(".{domain}"));
        } else if let Some(cidr) = ipv4_prefix_to_cidr(entry) {
            entries.push(cidr);
        } else {
            notes.push(format!(
                "the Windows bypass entry `{entry}` cannot be matched by jtm and is ignored"
            ));
        }
    }
    let bypass = (!entries.is_empty()).then(|| entries.join(","));
    (bypass, notes)
}

/// `10.*` as `10.0.0.0/8`, `192.168.*` as `192.168.0.0/16` and so on.
fn ipv4_prefix_to_cidr(entry: &str) -> Option<String> {
    let prefix = entry.strip_suffix(".*")?;
    let octets: Vec<u8> = prefix
        .split('.')
        .map(|part| part.parse::<u8>().ok())
        .collect::<Option<_>>()?;
    if octets.is_empty() || octets.len() > 3 {
        return None;
    }
    let mut address = octets.clone();
    address.resize(4, 0);
    let address: Vec<String> = address.iter().map(u8::to_string).collect();
    Some(format!("{}/{}", address.join("."), octets.len() * 8))
}

/// Reads the current user's WinINET settings. `None` when the key cannot be opened.
#[cfg(windows)]
pub fn read() -> Option<WinInetSettings> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        .ok()?;
    Some(WinInetSettings {
        enabled: key
            .get_value::<u32, _>("ProxyEnable")
            .is_ok_and(|value| value != 0),
        proxy_server: key.get_value::<String, _>("ProxyServer").ok(),
        proxy_override: key.get_value::<String, _>("ProxyOverride").ok(),
        auto_config_url: key.get_value::<String, _>("AutoConfigURL").ok(),
    })
}

/// There is no system proxy to read off Windows.
#[cfg(not(windows))]
pub fn read() -> Option<WinInetSettings> {
    None
}

#[cfg(test)]
mod tests;
