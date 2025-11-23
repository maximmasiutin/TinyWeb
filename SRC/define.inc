{$DEFINE LOGGING}

// STRICT_CGI_PARAMS: When enabled, CGI query parameters (ISINDEX-style queries
// without '=' per RFC 3875 Section 4.4) are validated against a whitelist of
// safe characters. Parameters containing characters outside [A-Za-z0-9._-/\:]
// will be rejected with HTTP 400 Bad Request.
//
// When disabled, Apache-style shell metacharacter escaping is used instead,
// which allows all characters but escapes dangerous ones. This provides full
// compatibility with legacy CGI scripts that may need special characters.
//
// Default: ENABLED (strictest security)
// To disable: Comment out or remove the line below
{$DEFINE STRICT_CGI_PARAMS}
