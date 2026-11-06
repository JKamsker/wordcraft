//! Server-rendered pages: the file browser at `/` and the "web app not built" page.
//!
//! No JavaScript, every value HTML-escaped, and only relative links, so the pages work behind a
//! reverse proxy that serves the server under a sub-path.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

use crate::storage::Entry;

/// Everything but unreserved characters (RFC 3986) is encoded in a query value or path segment.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

/// Escapes text for an HTML element or a quoted attribute.
pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// Percent-encodes one query value or path segment.
pub fn encode_component(s: &str) -> String {
    utf8_percent_encode(s, COMPONENT).to_string()
}

/// Percent-encodes a `/`-separated path segment by segment.
pub fn encode_path(path: &str) -> String {
    path.split('/').map(encode_component).collect::<Vec<_>>().join("/")
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS.get(unit).copied().unwrap_or("TB"))
}

const STYLE: &str = "\
:root{--bg:#f6f7f9;--card:#fff;--ink:#1d2330;--muted:#5f6b7a;--line:#dfe3e8;--accent:#2f6f5e;--danger:#a33a2c}
@media (prefers-color-scheme:dark){:root{--bg:#15181d;--card:#1e232a;--ink:#e6e9ee;--muted:#9aa5b1;--line:#333a44;--accent:#6fc2a8;--danger:#ef8a7a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 20px;overflow-wrap:anywhere}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.forms{display:flex;flex-wrap:wrap;gap:16px}
.forms form{display:flex;flex-wrap:wrap;gap:8px;align-items:center;flex:1 1 320px}
input[type=text]{flex:1 1 160px;min-width:0;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);font:inherit}
input[type=file]{flex:1 1 200px;min-width:0;font:inherit;color:var(--muted)}
button,a.btn{display:inline-block;padding:5px 12px;border:1px solid var(--accent);border-radius:6px;background:var(--accent);color:var(--card);font:inherit;text-decoration:none;cursor:pointer}
a.btn.ghost,button.ghost{background:transparent;color:var(--accent)}
button.danger{background:transparent;border-color:var(--danger);color:var(--danger)}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:middle}
th{color:var(--muted);font-weight:600;font-size:13px}
td.num{text-align:right;white-space:nowrap}
td.name{overflow-wrap:anywhere;font-weight:500}
td.folder{color:var(--muted);overflow-wrap:anywhere}
td.when{white-space:nowrap;color:var(--muted)}
td.actions{white-space:nowrap}
td.actions form{display:inline}
.empty{color:var(--muted);padding:12px 0}
.error{color:var(--danger)}
code{background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:1px 5px}
";

fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>{}</title><style>{STYLE}</style></head><body><main>{body}</main></body></html>\n",
        escape(title)
    )
}

/// The file browser. `files` may be an error message when the listing failed.
pub fn browser(storage: &str, files: Result<&[Entry], &str>) -> String {
    let mut body = String::new();
    body.push_str("<h1>WordCraft documents</h1>");
    body.push_str(&format!("<p class=\"sub\">Storage: {}</p>", escape(storage)));
    body.push_str(
        "<div class=\"card forms\">\
         <form method=\"get\" action=\"app/\"><label for=\"new\">New document</label>\
         <input type=\"text\" id=\"new\" name=\"new\" value=\"Document.docx\" required>\
         <button type=\"submit\">Create</button></form>\
         <form method=\"post\" action=\"upload\" enctype=\"multipart/form-data\">\
         <input type=\"file\" name=\"file\" required>\
         <input type=\"text\" name=\"folder\" placeholder=\"Folder (optional)\" aria-label=\"Folder\">\
         <button type=\"submit\" class=\"ghost\">Upload</button></form></div>",
    );
    body.push_str("<div class=\"card\">");
    match files {
        Err(message) => body.push_str(&format!("<p class=\"error\">Could not list the documents: {}</p>", escape(message))),
        Ok([]) => body.push_str("<p class=\"empty\">No documents yet. Create one or upload a file.</p>"),
        Ok(files) => {
            body.push_str(
                "<div class=\"scroll\"><table><thead><tr><th>Name</th><th>Folder</th><th class=\"num\">Size</th>\
                 <th>Modified</th><th></th></tr></thead><tbody>",
            );
            for e in files {
                let (folder, name) = e.path.rsplit_once('/').unwrap_or(("", &e.path));
                let when = e.modified.map(|m| m.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default();
                body.push_str(&format!(
                    "<tr><td class=\"name\">{name}</td><td class=\"folder\">{folder}</td><td class=\"num\">{size}</td>\
                     <td class=\"when\">{when}</td><td class=\"actions\">\
                     <a class=\"btn\" href=\"app/?file={edit}\">Edit</a> \
                     <a class=\"btn ghost\" href=\"api/files/{download}\" download>Download</a> \
                     <form method=\"post\" action=\"delete\"><input type=\"hidden\" name=\"path\" value=\"{path}\">\
                     <button type=\"submit\" class=\"danger\">Delete</button></form></td></tr>",
                    name = escape(name),
                    folder = escape(folder),
                    size = human_size(e.size),
                    when = escape(&when),
                    edit = escape(&encode_component(&e.path)),
                    download = escape(&encode_path(&e.path)),
                    path = escape(&e.path),
                ));
            }
            body.push_str("</tbody></table></div>");
        }
    }
    body.push_str("</div>");
    page("WordCraft documents", &body)
}

/// Shown at `/app/` when the web root has no `index.html`.
pub fn app_missing(web_root: &str) -> String {
    let body = format!(
        "<h1>The WordCraft web app is not built yet</h1>\
         <div class=\"card\"><p>The server looked for <code>index.html</code> in <code>{}</code> and found none.</p>\
         <p>Build the web app once, from the repository root:</p>\
         <p><code>cd apps/wordcraft-web &amp;&amp; trunk build --release</code></p>\
         <p>That writes <code>dist/web</code> at the repository root. Start the server from there, or pass \
         <code>--web-root &lt;folder&gt;</code>. Install the tools with \
         <code>rustup target add wasm32-unknown-unknown</code> and <code>cargo install trunk</code>.</p>\
         <p><a class=\"btn ghost\" href=\"../\">Back to the documents</a></p></div>",
        escape(web_root)
    );
    page("WordCraft web app not built", &body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_and_encodes() {
        assert_eq!(escape("<a href='x'>&\"</a>"), "&lt;a href=&#39;x&#39;&gt;&amp;&quot;&lt;/a&gt;");
        assert_eq!(encode_component("a b/c&d'é.docx"), "a%20b%2Fc%26d%27%C3%A9.docx");
        assert_eq!(encode_path("a b/c#d.docx"), "a%20b/c%23d.docx");
        assert_eq!(human_size(10), "10 B");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(u64::MAX), "16777216.0 TB");
    }
}
