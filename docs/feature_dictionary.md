# PhishGuard AI - URL Feature Dictionary (25 Dimensions)

This dictionary details the 25 lexical, structural, and syntactic features engineered in `ml/feature_extractor.py`.

| # | Feature Key | Type | Description & Cybersecurity Rationale | Phishing Example | Legitimate Example |
|---|---|---|---|---|---|
| 1 | `url_length` | int | Total character count. Phishers lengthen URLs to disguise domain names on mobile viewports. | `142` | `24` |
| 2 | `hostname_length` | int | Character length of the FQDN. Long hostnames often contain nested brand spoofing. | `68` | `14` |
| 3 | `path_length` | int | Length of URL path hierarchy. Deep subpaths mimic legitimate verification folders. | `84` | `12` |
| 4 | `query_length` | int | Length of query parameters. Phishers pass serialized tracking tokens. | `92` | `0` |
| 5 | `num_dots` | int | Total periods. Excessive dots indicate subdomain abuse or IP formatting. | `6` | `2` |
| 6 | `num_hyphens` | int | Total hyphens. Attackers concatenate brand names (`paypal-login-verify`). | `4` | `0` |
| 7 | `num_underscores` | int | Total underscores. Used in obfuscated directory naming. | `3` | `0` |
| 8 | `num_slashes` | int | Forward slashes indicating directory depth. | `7` | `3` |
| 9 | `num_question_marks` | int | Question marks. More than 1 suggests malformed or obfuscated query strings. | `2` | `1` |
| 10 | `num_equal_signs` | int | Equal signs in parameter assignments. | `5` | `1` |
| 11 | `num_ampersands` | int | Ampersands joining query parameters. | `4` | `0` |
| 12 | `num_percent` | int | Percentage characters used in percent-encoding (`%20`, `%2E`). | `6` | `0` |
| 13 | `has_at_symbol` | binary | Presence of `@`. Triggers credential-redirection vulnerability in web clients. | `1` | `0` |
| 14 | `has_ip_address` | binary | Hostname is an IPv4 or IPv6 address instead of a domain name. | `1` | `0` |
| 15 | `uses_https` | binary | Transport protocol encryption (`https` vs `http`). | `0` | `1` |
| 16 | `num_subdomains` | int | Count of nested subdomain components before the root domain. | `4` | `1` |
| 17 | `suspicious_keyword_count`| int | Occurrences of 25 credential harvesting tokens (`login`, `verify`, `banking`, etc.).| `3` | `0` |
| 18 | `is_url_shortener` | binary | Hostname matches known link-shortening proxies (`bit.ly`, `tinyurl`). | `1` | `0` |
| 19 | `hostname_entropy` | float | Shannon character entropy of the hostname. High entropy signifies DGA generation. | `4.12` | `2.64` |
| 20 | `digit_count` | int | Count of numeric digits across the entire URL. | `18` | `0` |
| 21 | `special_char_count` | int | Count of non-alphanumeric punctuation marks (`!$*+;=`). | `6` | `0` |
| 22 | `domain_path_ratio` | float | Ratio of path length relative to domain length. Deep phishing paths have high ratio. | `4.2` | `0.4` |
| 23 | `has_suspicious_tld` | binary | Domain ends in high-abuse TLD (`.tk`, `.ml`, `.xyz`, `.top`, `.loan`). | `1` | `0` |
| 24 | `encoded_char_count` | int | Frequency of `%XX` hex encoding patterns used to hide characters. | `4` | `0` |
| 25 | `has_double_slash_path`| binary | Path contains `//` after the protocol scheme, indicating open-redirect tricks. | `1` | `0` |
