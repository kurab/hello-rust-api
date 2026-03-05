//! DPoP htu handling helpers
//! We keep URL/environment-specific logic isolated here so other parts of
//! the DPoP verifier remain stable.
//!
use axum::http::Uri;

/// Build the expected htu (absolute URL) for the current request.
///
/// - If public_base_url is provided, we use its scheme/authority and append
///   the request's part-and-query.
/// - Otherwise, if request_uri is already absolute, we use it as-is.
///
/// The returned value is normalized (see ['normalize_htu']).
pub fn build_expected_htu(public_base_url: Option<&str>, request_uri: &Uri) -> Option<String> {
    // Prefer explicit public base URL (proxy/ingress aware)
    if let Some(base) = public_base_url {
        let base_uri: Uri = base.parse().ok()?;
        let scheme = base_uri.scheme_str()?;
        let authority = base_uri.authority()?.as_str();

        let pq = request_uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");

        // Ensure we always join with a leading '/'
        let joined = if pq.starts_with('/') {
            format!("{scheme}://{authority}{pq}")
        } else {
            format!("{scheme}://{authority}/{pq}")
        };

        return normalize_htu(&joined);
    }

    // Fallback: if request_uri itself is absolute.
    if request_uri.scheme().is_some() && request_uri.authority().is_some() {
        return normalize_htu(&request_uri.to_string());
    }

    None
}

/// Normalize an htu value for stable comparison.
///
/// Normalization rules (conservative / practical):
/// - Scheme and host are lowercased.
/// - Default ports (80 for http, 443 for https) are removed.
/// - Fragment is ignored (not representable in http::Uri anyway).
/// - Path is kept but trailing slash is removed (expect for "/").
/// - Query is preserved as-is.
pub fn normalize_htu(raw: &str) -> Option<String> {
    let uri: Uri = raw.parse().ok()?;
    normalize_absolute_uri(&uri)
}

fn normalize_absolute_uri(uri: &Uri) -> Option<String> {
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    let authority = uri.authority()?;

    let host = authority.host().to_ascii_lowercase();
    let port = authority.port_u16();

    // Drop default ports
    let include_port = match (scheme.as_str(), port) {
        ("http", Some(80)) => None,
        ("https", Some(443)) => None,
        (_, p) => p,
    };

    let mut path = uri.path();
    if path.is_empty() {
        path = "/";
    }

    // Remove trailing slash expect root.
    let mut path_owned = path.to_string();
    if path_owned.len() > 1 && path_owned.ends_with('/') {
        while path_owned.len() > 1 && path_owned.ends_with('/') {
            path_owned.pop();
        }
    }

    let query = uri.query();

    let authority_norm = if let Some(p) = include_port {
        format!("{host}:{p}")
    } else {
        host
    };

    let mut out = format!("{scheme}://{authority_norm}{path_owned}");
    if let Some(q) = query {
        out.push('?');
        out.push_str(q);
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_dpops_default_port_and_trailing_slash() {
        assert_eq!(
            normalize_htu("http://LOCALHOST:80/api/v1/users/").unwrap(),
            "http://localhost/api/v1/users"
        );
        assert_eq!(
            normalize_htu("https://example.com:443/resource").unwrap(),
            "https://example.com/resource"
        );
    }

    #[test]
    fn build_expected_htu_uses_public_base_url() {
        let req: Uri = "/api/v1/users?x=1".parse().unwrap();
        let out = build_expected_htu(Some("http://localhost:3001"), &req).unwrap();
        assert_eq!(out, "http://localhost:3001/api/v1/users?x=1");
    }
}
