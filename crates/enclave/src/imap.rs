//! A small read-only IMAP client for connected mailboxes. It only ever
//! sends LOGIN, LIST, EXAMINE (which opens a folder read-only), UID SEARCH,
//! UID FETCH with BODY.PEEK (which leaves messages unread) and LOGOUT, so
//! whatever the password allows, the agent can't change the mailbox.

use crate::net::{Net, Stream};
use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::Engine;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

const TIMEOUT: Duration = Duration::from_secs(60);
/// Bytes one command may return.
const MAX_READ: usize = 24 << 20;
/// Untagged responses (and literals) one command may return: what's kept
/// per response costs far more than a short line does to send.
const MAX_RESPONSES: usize = 200_000;
const MAX_LITERALS: usize = 20_000;
/// Bytes of one message fetched for reading.
const MAX_MESSAGE: usize = 4 << 20;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct Creds {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub user: String,
    pub password: String,
}

struct Session {
    io: BufReader<Stream>,
    tag: u32,
    read: usize,
}

/// One untagged response: its text, with each literal's bytes alongside.
struct Untagged {
    text: String,
    literals: Vec<Vec<u8>>,
}

fn quote(s: &str) -> Result<String> {
    ensure!(!s.chars().any(|c| c == '\r' || c == '\n' || c == '\0'), "line breaks aren't allowed");
    ensure!(s.is_ascii(), "only ASCII is supported here");
    Ok(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// The IMAP server for an address at one of the common providers. Other
/// domains get Gmail's, since a custom domain is most often Google Workspace.
pub fn server_for(address: &str) -> &'static str {
    let domain = address.rsplit('@').next().unwrap_or("").trim().to_ascii_lowercase();
    match domain.as_str() {
        "icloud.com" | "me.com" | "mac.com" => "imap.mail.me.com",
        "fastmail.com" | "fastmail.fm" => "imap.fastmail.com",
        "yahoo.com" | "ymail.com" => "imap.mail.yahoo.com",
        "aol.com" => "imap.aol.com",
        _ => "imap.gmail.com",
    }
}

/// Google shows app passwords as four groups of four letters; the spaces
/// aren't part of it.
pub fn clean_password(host: &str, password: &str) -> String {
    if host == "imap.gmail.com" {
        password.chars().filter(|c| !c.is_whitespace()).collect()
    } else {
        password.to_string()
    }
}

/// Say what to do about a refused login, for the providers whose replies
/// are known.
fn login_help(host: &str, reply: &str) -> String {
    if host != "imap.gmail.com" {
        return format!("the server refused the login: {reply}");
    }
    let r = reply.to_ascii_lowercase();
    if r.contains("application-specific password required") {
        "Gmail wants an app password here, not your Google password. Make one at https://myaccount.google.com/apppasswords and paste its 16 letters.".into()
    } else if r.contains("web login required") || r.contains("log in via your web browser") {
        "Google blocked this sign-in. Sign in to Gmail in your browser once, then try again with the app password.".into()
    } else if r.contains("authenticationfailed") || r.contains("invalid credentials") {
        "Gmail refused the address or app password. Check the address is the account the app password belongs to, and paste the 16-letter app password from https://myaccount.google.com/apppasswords (not your Google password). Google Workspace accounts also need their admin to allow app passwords.".into()
    } else {
        format!("Gmail refused the login: {reply}")
    }
}

impl Session {
    async fn open(net: &Net, c: &Creds) -> Result<Session> {
        let io = net.stream(&c.host, c.port, c.tls, Duration::from_secs(20)).await?;
        let mut s = Session { io: BufReader::new(io), tag: 0, read: 0 };
        let greeting = s.line().await?;
        let g = String::from_utf8_lossy(&greeting);
        ensure!(g.starts_with("* OK") || g.starts_with("* PREAUTH"), "the server didn't greet as IMAP: {}", g.trim());
        if !g.starts_with("* PREAUTH") {
            let cmd = format!("LOGIN {} {}", quote(&c.user)?, quote(&c.password)?);
            s.command(&cmd).await.map_err(|e| anyhow!(login_help(&c.host, &e.to_string())))?;
        }
        Ok(s)
    }

    async fn line(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let n = (&mut self.io).take(1 << 20).read_until(b'\n', &mut buf).await?;
        ensure!(n > 0, "the server closed the connection");
        self.read += n;
        ensure!(self.read <= MAX_READ, "the server sent too much");
        while buf.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
            buf.pop();
        }
        Ok(buf)
    }

    /// Send a command; return its untagged responses, or the server's error.
    async fn command(&mut self, cmd: &str) -> Result<Vec<Untagged>> {
        self.tag += 1;
        let tag = format!("a{}", self.tag);
        self.read = 0;
        self.io.get_mut().write_all(format!("{tag} {cmd}\r\n").as_bytes()).await?;
        self.io.get_mut().flush().await?;
        let mut out = Vec::new();
        let mut cur: Option<Untagged> = None;
        let mut literals = 0usize;
        loop {
            let line = self.line().await?;
            let text = String::from_utf8_lossy(&line).into_owned();
            // A line ending in {N} is followed by N bytes of literal data,
            // then the rest of the same response.
            let literal = text
                .strip_suffix('}')
                .and_then(|t| t.rsplit_once('{'))
                .and_then(|(_, n)| n.trim_end_matches('+').parse::<usize>().ok());
            let continuing = cur.is_some();
            let u = cur.get_or_insert_with(|| Untagged { text: String::new(), literals: Vec::new() });
            u.text.push_str(&text);
            if let Some(n) = literal {
                // Checked before allocating, without overflow: n is the
                // server's to choose.
                ensure!(n <= MAX_READ.saturating_sub(self.read), "the server sent too much");
                literals += 1;
                ensure!(literals <= MAX_LITERALS, "the server sent too many literals");
                let mut data = vec![0; n];
                self.io.read_exact(&mut data).await?;
                self.read += n;
                u.literals.push(data);
                continue;
            }
            let u = cur.take().unwrap();
            if !continuing && u.text.starts_with(&format!("{tag} ")) {
                let rest = &u.text[tag.len() + 1..];
                if rest.starts_with("OK") {
                    return Ok(out);
                }
                bail!("{}", rest.trim());
            }
            if u.text.starts_with("+") {
                bail!("the server asked for more input");
            }
            if u.text.is_empty() && u.literals.is_empty() {
                continue;
            }
            ensure!(out.len() < MAX_RESPONSES, "the server sent too many responses");
            out.push(u);
        }
    }

    async fn examine(&mut self, folder: &str) -> Result<()> {
        let f = if folder.is_empty() { "INBOX" } else { folder };
        self.command(&format!("EXAMINE {}", quote(f)?)).await.map_err(|e| anyhow!("can't open folder {f:?}: {e}"))?;
        Ok(())
    }

    async fn logout(mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(3), self.command("LOGOUT")).await;
    }
}

/// Log in and log out: checks the credentials when connecting.
pub async fn check(net: &Net, c: &Creds) -> Result<()> {
    tokio::time::timeout(TIMEOUT, async { Session::open(net, c).await?.logout().await; Ok(()) })
        .await
        .map_err(|_| anyhow!("the mail server timed out"))?
}

/// One request by the agent (the `email` tool).
pub async fn request(net: &Net, c: &Creds, args: &serde_json::Value) -> Result<String> {
    tokio::time::timeout(TIMEOUT, request_inner(net, c, args))
        .await
        .map_err(|_| anyhow!("the mail server timed out"))?
}

async fn request_inner(net: &Net, c: &Creds, args: &serde_json::Value) -> Result<String> {
    let action = args["action"].as_str().unwrap_or("");
    let folder = args["folder"].as_str().unwrap_or("INBOX").to_string();
    let mut s = Session::open(net, c).await?;
    let out = match action {
        "folders" => {
            let r = s.command("LIST \"\" \"*\"").await?;
            let mut lines = vec!["Folders (flags, delimiter, name; pass the name exactly as `folder`):".to_string()];
            lines.extend(r.iter().filter_map(|u| u.text.strip_prefix("* LIST ").map(String::from)));
            lines.join("\n")
        }
        "search" => {
            let criteria = args["query"].as_str().map(str::trim).filter(|q| !q.is_empty()).unwrap_or("ALL");
            ensure!(criteria.len() <= 1000, "the query is too long");
            ensure!(
                criteria.chars().all(|c| (' '..='~').contains(&c)) && !criteria.contains('{'),
                "the query must be printable ASCII on one line (IMAP SEARCH syntax), without literals"
            );
            let max = args["max_results"].as_u64().unwrap_or(30).clamp(1, 100) as usize;
            s.examine(&folder).await?;
            let r = s.command(&format!("UID SEARCH {criteria}")).await.map_err(|e| anyhow!("search failed: {e}"))?;
            let mut uids: Vec<u64> = r
                .iter()
                .filter_map(|u| u.text.strip_prefix("* SEARCH"))
                .flat_map(|t| t.split_whitespace().filter_map(|x| x.parse().ok()).collect::<Vec<u64>>())
                .collect();
            uids.sort_unstable();
            let total = uids.len();
            let newest: Vec<u64> = uids.iter().rev().take(max).copied().collect();
            let mut lines = vec![format!(
                "{total} message(s) in {folder} match; {} newest shown (uid | date | from | to | subject). Read one with action \"read\" and its uid.",
                newest.len()
            )];
            if !newest.is_empty() {
                let set = newest.iter().map(|u| u.to_string()).collect::<Vec<_>>().join(",");
                let r = s.command(&format!("UID FETCH {set} (UID BODY.PEEK[HEADER.FIELDS (DATE FROM TO SUBJECT)])")).await?;
                let mut rows: Vec<(u64, String)> = r
                    .iter()
                    .filter(|u| u.text.contains("FETCH"))
                    .filter_map(|u| {
                        let uid = u.text.split("UID ").nth(1)?.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
                        let h = headers(u.literals.first().map(|l| &l[..]).unwrap_or(b""));
                        let g = |k: &str| h.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.as_str()).unwrap_or("");
                        Some((uid, format!("{uid} | {} | {} | {} | {}", g("date"), g("from"), g("to"), g("subject"))))
                    })
                    .collect();
                rows.sort_by(|a, b| b.0.cmp(&a.0));
                lines.extend(rows.into_iter().map(|(_, r)| r));
            }
            lines.join("\n")
        }
        "read" => {
            let uid = args["uid"].as_u64().or_else(|| args["uid"].as_str().and_then(|s| s.parse().ok())).context("uid is required")?;
            s.examine(&folder).await?;
            let r = s.command(&format!("UID FETCH {uid} (UID BODY.PEEK[]<0.{MAX_MESSAGE}>)")).await?;
            let raw = r.iter().find(|u| u.text.contains("FETCH") && !u.literals.is_empty()).map(|u| u.literals[0].clone());
            match raw {
                Some(raw) => render_message(&raw),
                None => format!("no message with uid {uid} in {folder}"),
            }
        }
        _ => bail!("action must be folders, search or read"),
    };
    s.logout().await;
    Ok(out)
}

// ------------------------------------------------------------ messages

/// Header fields, unfolded and with encoded words decoded.
fn headers(raw: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(raw);
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.split('\n') {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some(last) = out.last_mut() {
                last.1.push(' ');
                last.1.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    for h in &mut out {
        h.1 = decode_words(&h.1);
    }
    out
}

/// RFC 2047 encoded words: =?charset?B|Q?text?=
fn decode_words(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    let mut last_was_word = false;
    while let Some(i) = rest.find("=?") {
        let before = &rest[..i];
        let after = &rest[i + 2..];
        let decoded = (|| {
            let mut it = after.splitn(3, '?');
            let charset = it.next()?;
            let enc = it.next()?;
            let tail = it.next()?;
            let end = tail.find("?=")?;
            let data = &tail[..end];
            let bytes = match enc.to_ascii_uppercase().as_str() {
                "B" => base64::engine::general_purpose::STANDARD.decode(data).ok()?,
                "Q" => qp(data.replace('_', " ").as_bytes(), false),
                _ => return None,
            };
            Some((charset_decode(&bytes, charset), 2 + charset.len() + 1 + enc.len() + 1 + end + 2))
        })();
        match decoded {
            Some((text, used)) => {
                if !(last_was_word && before.trim().is_empty()) {
                    out.push_str(before);
                }
                out.push_str(&text);
                rest = &rest[i + used..];
                last_was_word = true;
            }
            None => {
                out.push_str(&rest[..i + 2]);
                rest = &rest[i + 2..];
                last_was_word = false;
            }
        }
    }
    out.push_str(rest);
    out
}

fn qp(data: &[u8], soft_breaks: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'=' {
            if soft_breaks && data.get(i + 1) == Some(&b'\r') && data.get(i + 2) == Some(&b'\n') {
                i += 3;
                continue;
            }
            if soft_breaks && data.get(i + 1) == Some(&b'\n') {
                i += 2;
                continue;
            }
            if let (Some(a), Some(b)) = (data.get(i + 1), data.get(i + 2)) {
                if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(&[*a, *b]), 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

fn charset_decode(b: &[u8], charset: &str) -> String {
    let c = charset.to_ascii_lowercase();
    if c.contains("8859-1") || c.contains("1252") || c == "latin1" {
        b.iter().map(|&x| x as char).collect()
    } else {
        String::from_utf8_lossy(b).into_owned()
    }
}

/// A header value's parameter, e.g. boundary or charset.
fn param(v: &str, name: &str) -> Option<String> {
    v.split(';').skip(1).find_map(|p| {
        let (k, val) = p.split_once('=')?;
        k.trim().eq_ignore_ascii_case(name).then(|| val.trim().trim_matches('"').to_string())
    })
}

fn split_head_body(raw: &[u8]) -> (&[u8], &[u8]) {
    for (i, w) in raw.windows(2).enumerate() {
        if w == b"\n\n" {
            return (&raw[..i + 1], &raw[i + 2..]);
        }
        if i + 4 <= raw.len() && &raw[i..i + 4] == b"\r\n\r\n" {
            return (&raw[..i + 2], &raw[i + 4..]);
        }
    }
    (raw, b"")
}

fn strip_html(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::new();
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < s.len() {
        if bytes[i] == b'<' {
            for skip in ["<style", "<script"] {
                if lower[i..].starts_with(skip) {
                    let close = format!("</{}", &skip[1..]);
                    i = lower[i..].find(&close).map(|j| i + j).unwrap_or(s.len());
                    break;
                }
            }
            let end = s[i..].find('>').map(|j| i + j + 1).unwrap_or(s.len());
            let tag = &lower[i..end];
            if tag.starts_with("<br") || tag.starts_with("<p") || tag.starts_with("</p") || tag.starts_with("<div") || tag.starts_with("<tr") || tag.starts_with("<li") {
                out.push('\n');
            }
            i = end;
        } else {
            let next = s[i..].find('<').map(|j| i + j).unwrap_or(s.len());
            out.push_str(&s[i..next]);
            i = next;
        }
    }
    let out = out.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'");
    out.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("\n")
}

/// One MIME part, as text: text parts decoded, others listed.
fn render_part(raw: &[u8], depth: usize, out: &mut String) {
    let (head, body) = split_head_body(raw);
    let h = headers(head);
    let g = |k: &str| h.iter().find(|(n, _)| n.eq_ignore_ascii_case(k)).map(|(_, v)| v.clone()).unwrap_or_default();
    let ctype = g("content-type");
    let mime = ctype.split(';').next().unwrap_or("text/plain").trim().to_ascii_lowercase();
    let mime = if mime.is_empty() { "text/plain".to_string() } else { mime };
    let cte = g("content-transfer-encoding").to_ascii_lowercase();
    let decode = |b: &[u8]| -> Vec<u8> {
        match cte.trim() {
            "base64" => {
                let clean: Vec<u8> = b.iter().copied().filter(|c| !c.is_ascii_whitespace()).collect();
                base64::engine::general_purpose::STANDARD.decode(&clean).unwrap_or_else(|_| b.to_vec())
            }
            "quoted-printable" => qp(b, true),
            _ => b.to_vec(),
        }
    };
    if depth > 8 {
        return;
    }
    if mime.starts_with("multipart/") {
        let Some(boundary) = param(&ctype, "boundary") else { return };
        let delim = format!("--{boundary}");
        let text = body;
        let mut parts: Vec<&[u8]> = Vec::new();
        let mut start: Option<usize> = None;
        let mut i = 0;
        while i < text.len() {
            let line_end = text[i..].iter().position(|&c| c == b'\n').map(|j| i + j + 1).unwrap_or(text.len());
            let line = &text[i..line_end];
            let l = String::from_utf8_lossy(line);
            let l = l.trim_end();
            if l == delim || l == format!("{delim}--") {
                if let Some(s) = start {
                    parts.push(&text[s..i]);
                }
                if l.ends_with("--") && l != delim {
                    break;
                }
                start = Some(line_end);
            }
            i = line_end;
        }
        if mime == "multipart/alternative" {
            // Prefer the plain-text version.
            let pick = parts
                .iter()
                .find(|p| String::from_utf8_lossy(split_head_body(p).0).to_ascii_lowercase().contains("text/plain"))
                .or(parts.first());
            if let Some(p) = pick {
                render_part(p, depth + 1, out);
            }
        } else {
            for p in parts {
                render_part(p, depth + 1, out);
            }
        }
        return;
    }
    let disposition = g("content-disposition");
    let filename = param(&disposition, "filename").or_else(|| param(&ctype, "name"));
    if mime == "message/rfc822" {
        out.push_str("\n--- attached message ---\n");
        render_message_into(&decode(body), depth + 1, out);
        return;
    }
    if mime.starts_with("text/") && !disposition.to_ascii_lowercase().starts_with("attachment") {
        let text = charset_decode(&decode(body), &param(&ctype, "charset").unwrap_or_default());
        let text = if mime == "text/html" { strip_html(&text) } else { text };
        out.push('\n');
        out.push_str(text.trim());
        out.push('\n');
    } else {
        out.push_str(&format!(
            "\n[attachment: {} ({mime}, about {} bytes); attachment contents aren't available]\n",
            filename.unwrap_or_else(|| "unnamed".into()),
            decode(body).len()
        ));
    }
}

fn render_message_into(raw: &[u8], depth: usize, out: &mut String) {
    let (head, _) = split_head_body(raw);
    for (k, v) in headers(head) {
        if ["date", "from", "to", "cc", "subject", "message-id", "in-reply-to", "reply-to"].iter().any(|n| k.eq_ignore_ascii_case(n)) {
            out.push_str(&format!("{k}: {v}\n"));
        }
    }
    render_part(raw, depth, out);
}

pub fn render_message(raw: &[u8]) -> String {
    let mut out = String::new();
    render_message_into(raw, 0, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_messages() {
        assert_eq!(decode_words("=?UTF-8?B?SW52b2ljZSDinJM=?= paid"), "Invoice ✓ paid");
        assert_eq!(decode_words("=?iso-8859-1?Q?Caf=E9_bill?="), "Café bill");
        assert_eq!(decode_words("a =?utf-8?q?x?= =?utf-8?q?y?= b"), "a xy b");
        let raw = b"From: Ann <ann@x.com>\r\nSubject: =?utf-8?q?Q3_numbers?=\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\npreamble\r\n--b1\r\nContent-Type: multipart/alternative; boundary=b2\r\n\r\n--b2\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nRevenue was =E2=82=AC5m, so=\r\nft break.\r\n--b2\r\nContent-Type: text/html\r\n\r\n<p>html</p>\r\n--b2--\r\n--b1\r\nContent-Type: application/pdf; name=\"q3.pdf\"\r\nContent-Disposition: attachment; filename=\"q3.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0x\r\n--b1--\r\n";
        let t = render_message(raw);
        assert!(t.contains("Subject: Q3 numbers"), "{t}");
        assert!(t.contains("Revenue was €5m, soft break."), "{t}");
        assert!(!t.contains("html"), "{t}");
        assert!(t.contains("[attachment: q3.pdf (application/pdf, about 6 bytes)"), "{t}");
        assert_eq!(strip_html("<style>x{}</style><p>Hi&nbsp;there</p><br>ok"), "Hi there\nok");
    }

    #[test]
    fn quoting() {
        assert_eq!(quote("a\"b\\c").unwrap(), "\"a\\\"b\\\\c\"");
        assert!(quote("x\r\nA2 DELETE INBOX").is_err());
    }
}
