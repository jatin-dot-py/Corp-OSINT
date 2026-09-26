# Phase 3 conclusion: forming crawl links from a homepage

- Parse active HTML navigation: `<a href>` and `<area href>`. Treat `<frame src>` and a meta refresh as explicit handoffs to another page. Do not infer crawl links from comments, scripts, JSON, CSS, images, or other asset references.
- Resolve each target against the **final response URL** using URL joining. Honor an HTML `<base href>` when present. This covers relative paths, `/` paths, `../` paths, query-only links, and protocol-relative links.
- Decode HTML entities, percent-encode spaces and other invalid URL characters, remove fragments, and deduplicate the resulting URLs. Keep only valid public HTTP(S) targets; discard empty, `javascript:`, `mailto:`, `tel:`, `data:`, localhost, and private-address targets.

