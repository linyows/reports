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

/// Free a string returned by reports_list or reports_show.
void reports_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* REPORTS_H */
