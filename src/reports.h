#ifndef REPORTS_H
#define REPORTS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Initialize the reports library. Call once at startup.
void reports_init(void);

/// Cleanup the reports library. Call once at shutdown.
void reports_deinit(void);

/// Fetch reports from all configured IMAP accounts.
/// @param config_json JSON string with configuration.
/// @return 0 on success, -1 on error.
int reports_fetch(const char *config_json);

/// Fetch reports for a specific account only.
/// @param config_json JSON string with configuration.
/// @param account_name The account name to fetch.
/// @return NULL on success, or error message string on failure. Free with reports_free_string().
char *reports_fetch_account(const char *config_json, const char *account_name);

/// Enrich all source IPs with PTR, ASN, and country info.
/// @param config_json JSON string with configuration.
/// @return 0 on success, -1 on error.
int reports_enrich(const char *config_json);

/// Rebuild dashboard and mail sources caches.
/// @param config_json JSON string with configuration.
/// @return 0 on success, -1 on error.
int reports_aggregate(const char *config_json);

/// Sync: fetch + enrich + aggregate in one call.
/// @param config_json JSON string with configuration.
/// @return 0 on success, -1 on error.
int reports_sync(const char *config_json);

/// List all stored reports across all accounts.
/// @param config_json JSON string with configuration.
/// @return JSON array string, or NULL on error. Free with reports_free_string().
char *reports_list(const char *config_json);

/// Show a specific report.
/// @param config_json JSON string with configuration.
/// @param report_type "dmarc" or "tlsrpt".
/// @param account_name The account name.
/// @param filename The report filename.
/// @return JSON string, or NULL on error. Free with reports_free_string().
char *reports_show(const char *config_json, const char *report_type,
                   const char *account_name, const char *filename);

/// Aggregate dashboard statistics across all reports.
/// @param config_json JSON string with configuration.
/// @return JSON string, or NULL on error. Free with reports_free_string().
char *reports_dashboard(const char *config_json);

/// Aggregate mail sources across all reports.
/// @param config_json JSON string with configuration.
/// @return JSON array string, or NULL on error. Free with reports_free_string().
char *reports_sources(const char *config_json);

/// Enrich an IP address with PTR, ASN, organization, and country info.
/// @param ip The IP address string (IPv4 or IPv6).
/// @return JSON string, or NULL on error. Free with reports_free_string().
char *reports_enrich_ip(const char *ip);

/// Free a string returned by reports_list, reports_show, or reports_enrich_ip.
void reports_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* REPORTS_H */
