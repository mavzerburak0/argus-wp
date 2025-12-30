"""
Slack notification module for sending formatted scan results to Slack.
"""
import requests
from typing import Dict, List, Any
from datetime import datetime


class SlackNotifier:
    """
    Handles sending formatted WordPress scan results to Slack via webhook.
    """

    # Emoji mappings for different severity levels and issues
    SEVERITY_EMOJI = {
        'critical': ':rotating_light:',
        'high': ':red_circle:',
        'medium': ':large_orange_diamond:',
        'low': ':large_blue_diamond:',
        'info': ':information_source:'
    }

    # Color codes for Slack message attachments
    SEVERITY_COLORS = {
        'critical': '#8B0000',  # Dark red
        'high': '#FF0000',      # Red
        'medium': '#FFA500',    # Orange
        'low': '#4169E1',       # Royal blue
        'info': '#808080'       # Gray
    }

    # Issue-specific emojis
    ISSUE_EMOJI = {
        'outdated': ':warning:',
        'vulnerable': ':skull_and_crossbones:',
        'xmlrpc': ':lock:',
        'directory_listing': ':open_file_folder:',
        'user_registration': ':bust_in_silhouette:',
        'success': ':white_check_mark:',
        'scan': ':mag:',
        'wordpress': ':wordpress:',
        'plugin': ':electric_plug:',
        'theme': ':art:',
        'info': ':information_source:',
        'warning': ':warning:'
    }

    def __init__(self, webhook_url: str):
        """
        Initialize Slack notifier.

        Args:
            webhook_url: Slack webhook URL
        """
        self.webhook_url = webhook_url

    def send_scan_results(self, scan_data: Dict[str, Any], is_batch: bool = False) -> bool:
        """
        Send scan results to Slack.

        Args:
            scan_data: Scan results dictionary
            is_batch: Whether this is a batch scan result

        Returns:
            True if message was sent successfully
        """
        if is_batch:
            message = self._format_batch_results(scan_data)
        else:
            message = self._format_single_result(scan_data)

        return self._send_message(message)

    def _format_single_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format a single scan result for Slack with detailed information.

        Args:
            result: Single scan result dictionary

        Returns:
            Formatted Slack message payload
        """
        blocks = []
        attachments = []

        # Header
        target_url = result.get('target_url', 'Unknown')
        wp_detected = result.get('wordpress_detected', False)

        if not wp_detected:
            # WordPress not detected
            blocks.append({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{self.ISSUE_EMOJI['scan']} WordPress Scan: {target_url}"
                }
            })
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{self.ISSUE_EMOJI['info']} *WordPress not detected on this target*"
                }
            })
            return {"blocks": blocks}

        # Calculate total vulnerabilities
        wp_vulns = len(result.get('wordpress_vulnerabilities', []))
        plugin_vulns = sum(p.get('vulnerability_count', 0) for p in result.get('plugins', []))
        theme_vulns = sum(t.get('vulnerability_count', 0) for t in result.get('themes', []))
        total_vulns = wp_vulns + plugin_vulns + theme_vulns

        # Determine overall severity
        severity = self._determine_overall_severity(result)

        # Header with emoji based on findings (only for vulnerabilities)
        header_text = f"WordPress Scan: {target_url}"
        if total_vulns > 0:
            header_emoji = self.SEVERITY_EMOJI.get(severity, self.ISSUE_EMOJI['scan'])
            header_text = f"{header_emoji} {header_text}"

        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": header_text
            }
        })

        # WordPress Version and Summary
        wp_version = result.get('wordpress_version', 'Unknown')
        wp_latest_version = result.get('wordpress_latest_version')
        wp_is_outdated = result.get('wordpress_is_outdated', False)

        # Display WordPress version with update status
        wp_version_text = f"`{wp_version}`"
        if wp_latest_version:
            if wp_is_outdated:
                wp_version_text = f"`{wp_version}` (latest: v{wp_latest_version})"
            else:
                wp_version_text = f"`{wp_version}` (up to date)"

        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*{self.ISSUE_EMOJI['wordpress']} WordPress Version:*\n{wp_version_text}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Total Vulnerabilities:*\n{total_vulns}"
                }
            ]
        })

        blocks.append({"type": "divider"})

        # WordPress Core Vulnerabilities (Detailed)
        if wp_vulns > 0:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{self.ISSUE_EMOJI['vulnerable']} WordPress Core Vulnerabilities ({wp_vulns})*"
                }
            })

            for vuln in result.get('wordpress_vulnerabilities', []):
                attachment = self._create_vulnerability_attachment(vuln, 'WordPress Core')
                attachments.append(attachment)

        # Plugins Section - Show ALL plugins with detailed info
        plugins = result.get('plugins', [])
        if plugins:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{self.ISSUE_EMOJI['plugin']} Installed Plugins ({len(plugins)})*"
                }
            })

            plugin_list = []
            vulnerable_plugins = []

            for plugin in plugins:
                plugin_name = plugin.get('slug', 'Unknown')
                plugin_version = plugin.get('version', 'Unknown')
                vuln_count = plugin.get('vulnerability_count', 0)

                if vuln_count > 0:
                    plugin_emoji = self.SEVERITY_EMOJI['high']
                    plugin_list.append(
                        f"{plugin_emoji} `{plugin_name}` v{plugin_version} - *{vuln_count} vulnerabilit{'y' if vuln_count == 1 else 'ies'}*"
                    )
                    vulnerable_plugins.append(plugin)
                else:
                    # Display version with update status from scan results
                    latest_version = plugin.get('latest_version')
                    is_outdated = plugin.get('is_outdated', False)

                    version_text = f"v{plugin_version}"
                    if latest_version:
                        if is_outdated:
                            version_text = f"{version_text} (latest: v{latest_version})"
                        else:
                            version_text = f"{version_text} (up to date)"
                    else:
                        # Couldn't retrieve version info (likely premium/commercial plugin)
                        version_text = f"{version_text} (version status unknown)"

                    plugin_list.append(f"`{plugin_name}` {version_text}")

            # Display plugin list
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": '\n'.join(plugin_list[:15])  # Limit to 15 to avoid message size issues
                }
            })

            if len(plugin_list) > 15:
                blocks.append({
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": f"_...and {len(plugin_list) - 15} more plugins_"
                    }]
                })

            # Show detailed vulnerability info for vulnerable plugins
            if vulnerable_plugins:
                blocks.append({"type": "divider"})
                for plugin in vulnerable_plugins:
                    plugin_name = plugin.get('slug', 'Unknown')
                    plugin_version = plugin.get('version', 'Unknown')
                    vulns = plugin.get('vulnerabilities', [])

                    for vuln in vulns[:2]:  # Show top 2 vulnerabilities per plugin
                        attachment = self._create_vulnerability_attachment(
                            vuln,
                            f"Plugin: {plugin_name} v{plugin_version}"
                        )
                        attachments.append(attachment)

        # Themes Section - Show ALL themes with detailed info
        themes = result.get('themes', [])
        if themes:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{self.ISSUE_EMOJI['theme']} Installed Themes ({len(themes)})*"
                }
            })

            theme_list = []
            vulnerable_themes = []

            for theme in themes:
                theme_name = theme.get('slug', 'Unknown')
                theme_version = theme.get('version', 'Unknown')
                vuln_count = theme.get('vulnerability_count', 0)

                if vuln_count > 0:
                    theme_emoji = self.SEVERITY_EMOJI['high']
                    theme_list.append(
                        f"{theme_emoji} `{theme_name}` v{theme_version} - *{vuln_count} vulnerabilit{'y' if vuln_count == 1 else 'ies'}*"
                    )
                    vulnerable_themes.append(theme)
                else:
                    # Display version with update status from scan results
                    latest_version = theme.get('latest_version')
                    is_outdated = theme.get('is_outdated', False)

                    version_text = f"v{theme_version}"
                    if latest_version:
                        if is_outdated:
                            version_text = f"{version_text} (latest: v{latest_version})"
                        else:
                            version_text = f"{version_text} (up to date)"
                    else:
                        # Couldn't retrieve version info (likely premium/commercial theme)
                        version_text = f"{version_text} (version status unknown)"

                    theme_list.append(f"`{theme_name}` {version_text}")

            # Display theme list
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": '\n'.join(theme_list)
                }
            })

            # Show detailed vulnerability info for vulnerable themes
            if vulnerable_themes:
                blocks.append({"type": "divider"})
                for theme in vulnerable_themes:
                    theme_name = theme.get('slug', 'Unknown')
                    theme_version = theme.get('version', 'Unknown')
                    vulns = theme.get('vulnerabilities', [])

                    for vuln in vulns[:2]:  # Show top 2 vulnerabilities per theme
                        attachment = self._create_vulnerability_attachment(
                            vuln,
                            f"Theme: {theme_name} v{theme_version}"
                        )
                        attachments.append(attachment)

        # Security Configuration Details
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{self.ISSUE_EMOJI['xmlrpc']} Security Configuration*"
            }
        })

        security_fields = []

        # XML-RPC
        xmlrpc_enabled = result.get('xmlrpc_enabled', False)
        xmlrpc_emoji = self.ISSUE_EMOJI['warning'] if xmlrpc_enabled else self.ISSUE_EMOJI['success']
        security_fields.append({
            "type": "mrkdwn",
            "text": f"*XML-RPC:*\n{xmlrpc_emoji} {'Enabled' if xmlrpc_enabled else 'Disabled'}"
        })

        # WP-Cron
        wp_cron_enabled = result.get('wp_cron_enabled', False)
        security_fields.append({
            "type": "mrkdwn",
            "text": f"*WP-Cron:*\n{self.ISSUE_EMOJI['info']} {'Enabled' if wp_cron_enabled else 'Disabled'}"
        })

        # User Registration
        user_reg_enabled = result.get('user_registration_enabled', False)
        user_reg_emoji = self.ISSUE_EMOJI['warning'] if user_reg_enabled else self.ISSUE_EMOJI['success']
        security_fields.append({
            "type": "mrkdwn",
            "text": f"*User Registration:*\n{user_reg_emoji} {'Enabled' if user_reg_enabled else 'Disabled'}"
        })

        # Directory Listing
        directory_listings = result.get('directory_listings', [])
        if directory_listings:
            dir_emoji = self.ISSUE_EMOJI['warning']
            security_fields.append({
                "type": "mrkdwn",
                "text": f"*Directory Listing:*\n{dir_emoji} {len(directory_listings)} found"
            })
        else:
            dir_emoji = self.ISSUE_EMOJI['success']
            security_fields.append({
                "type": "mrkdwn",
                "text": f"*Directory Listing:*\n{dir_emoji} None found"
            })

        blocks.append({
            "type": "section",
            "fields": security_fields
        })

        # Additional Security Issues
        additional_issues = []

        if directory_listings:
            additional_issues.append(f"{self.ISSUE_EMOJI['directory_listing']} Directory listings: {', '.join(directory_listings[:3])}")

        config_backups = result.get('config_backups', [])
        if config_backups:
            additional_issues.append(f"{self.ISSUE_EMOJI['warning']} Config backups exposed: {len(config_backups)}")

        db_dumps = result.get('db_dumps', [])
        if db_dumps:
            additional_issues.append(f"{self.ISSUE_EMOJI['warning']} Database dumps found: {len(db_dumps)}")

        exposed_files = result.get('exposed_files', [])
        if exposed_files:
            additional_issues.append(f"{self.ISSUE_EMOJI['warning']} Exposed files: {len(exposed_files)}")

        if additional_issues:
            blocks.append({"type": "divider"})
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{self.ISSUE_EMOJI['warning']} Additional Security Issues:*\n" + '\n'.join(f"• {issue}" for issue in additional_issues)
                }
            })

        # Footer
        blocks.append({"type": "divider"})

        scan_duration = ""
        if result.get('scan_duration'):
            scan_duration = f" | Duration: {result.get('scan_duration'):.2f}s"

        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Scanned at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{scan_duration} | Powered by Argus-WP"
                }
            ]
        })

        return {
            "blocks": blocks,
            "attachments": attachments
        }

    def _format_batch_results(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format batch scan results for Slack.

        Args:
            data: Batch scan data with scan_summary and results

        Returns:
            Formatted Slack message payload
        """
        blocks = []

        summary = data.get('scan_summary', {})
        results = data.get('results', [])

        total_targets = summary.get('total_targets', 0)
        successful = summary.get('successful_scans', 0)
        failed = summary.get('failed_scans', 0)
        total_vulns = summary.get('total_vulnerabilities', 0)
        vulnerable_sites = summary.get('vulnerable_sites', 0)

        # Determine emoji based on findings
        if total_vulns > 0:
            header_emoji = self.SEVERITY_EMOJI['high']
        else:
            header_emoji = self.ISSUE_EMOJI['success']

        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{header_emoji} Batch WordPress Security Scan Results"
            }
        })

        # Summary
        blocks.append({
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Total Targets:*\n{total_targets}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Successful Scans:*\n{successful}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Failed Scans:*\n{failed}"
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Total Vulnerabilities:*\n{total_vulns}"
                }
            ]
        })

        if vulnerable_sites > 0:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{self.ISSUE_EMOJI['vulnerable']} *{vulnerable_sites} of {successful} sites have vulnerabilities*"
                }
            })
        else:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{self.ISSUE_EMOJI['success']} *No vulnerabilities found in any scanned sites*"
                }
            })

        blocks.append({"type": "divider"})

        # Individual site summaries (vulnerable sites only)
        vulnerable_results = [r for r in results if self._has_vulnerabilities(r)]

        if vulnerable_results:
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Vulnerable Sites:*"
                }
            })

            for result in vulnerable_results[:10]:  # Limit to 10 sites
                target_url = result.get('target_url', 'Unknown')
                wp_vulns = len(result.get('wordpress_vulnerabilities', []))
                plugin_vulns = sum(p.get('vulnerability_count', 0) for p in result.get('plugins', []))
                theme_vulns = sum(t.get('vulnerability_count', 0) for t in result.get('themes', []))
                total = wp_vulns + plugin_vulns + theme_vulns

                severity = self._determine_overall_severity(result)
                emoji = self.SEVERITY_EMOJI.get(severity, self.ISSUE_EMOJI['vulnerable'])

                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{target_url}*\n{total} vulnerabilities (WP: {wp_vulns}, Plugins: {plugin_vulns}, Themes: {theme_vulns})"
                    }
                })

        # Footer
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Scanned at {summary.get('scan_timestamp', datetime.now().isoformat())} | Powered by Argus-WP"
                }
            ]
        })

        return {"blocks": blocks}

    def _create_vulnerability_attachment(self, vuln: Dict[str, Any], component_name: str) -> Dict[str, Any]:
        """
        Create a Slack attachment for a vulnerability.

        Args:
            vuln: Vulnerability dictionary
            component_name: Name of the affected component

        Returns:
            Slack attachment dictionary
        """
        severity = vuln.get('severity', 'medium').lower()
        color = self.SEVERITY_COLORS.get(severity, self.SEVERITY_COLORS['info'])

        cve_id = vuln.get('cve_id', 'Unknown')
        summary = vuln.get('summary', 'No description available')

        # Convert cvss_score to float, handle both string and numeric values
        cvss_score_raw = vuln.get('cvss_score', 0.0)
        try:
            cvss_score = float(cvss_score_raw) if cvss_score_raw else 0.0
        except (ValueError, TypeError):
            cvss_score = 0.0

        version_range = vuln.get('version_range', '')
        unfixed = vuln.get('unfixed', False)

        # Truncate summary if too long
        if len(summary) > 200:
            summary = summary[:200] + '...'

        fields = [
            {
                "title": "Severity",
                "value": f"{self.SEVERITY_EMOJI.get(severity, '')} {severity.upper()}",
                "short": True
            }
        ]

        if cvss_score > 0:
            fields.append({
                "title": "CVSS Score",
                "value": str(cvss_score),
                "short": True
            })

        if version_range:
            fields.append({
                "title": "Affected Versions",
                "value": version_range,
                "short": True
            })

        if unfixed:
            fields.append({
                "title": "Status",
                "value": f"{self.ISSUE_EMOJI['warning']} UNFIXED - No patch available!",
                "short": True
            })

        attachment = {
            "color": color,
            "title": f"{cve_id} - {component_name}",
            "text": summary,
            "fields": fields,
            "footer": "Argus-WP Scanner",
            "footer_icon": "https://api.slack.com/img/blocks/bkb_template_images/notificationsWarningIcon.png"
        }

        # Add reference link if available
        references = vuln.get('references', [])
        if references:
            attachment['title_link'] = references[0]

        return attachment

    def _build_summary_text(self, result: Dict[str, Any], total_vulns: int) -> str:
        """
        Build summary text for a scan result.

        Args:
            result: Scan result dictionary
            total_vulns: Total number of vulnerabilities

        Returns:
            Formatted summary text
        """
        if total_vulns == 0:
            return f"{self.ISSUE_EMOJI['success']} *No vulnerabilities detected!*"

        wp_vulns = len(result.get('wordpress_vulnerabilities', []))
        plugin_count = len(result.get('plugins', []))
        theme_count = len(result.get('themes', []))

        summary_parts = [f"{self.ISSUE_EMOJI['vulnerable']} *Found {total_vulns} vulnerabilit{'y' if total_vulns == 1 else 'ies'}*"]

        if wp_vulns > 0:
            summary_parts.append(f"• WordPress Core: {wp_vulns}")

        vulnerable_plugins = [p for p in result.get('plugins', []) if p.get('vulnerability_count', 0) > 0]
        if vulnerable_plugins:
            plugin_vuln_count = sum(p.get('vulnerability_count', 0) for p in vulnerable_plugins)
            summary_parts.append(f"• Plugins: {plugin_vuln_count} ({len(vulnerable_plugins)}/{plugin_count} vulnerable)")

        vulnerable_themes = [t for t in result.get('themes', []) if t.get('vulnerability_count', 0) > 0]
        if vulnerable_themes:
            theme_vuln_count = sum(t.get('vulnerability_count', 0) for t in vulnerable_themes)
            summary_parts.append(f"• Themes: {theme_vuln_count} ({len(vulnerable_themes)}/{theme_count} vulnerable)")

        return '\n'.join(summary_parts)

    def _collect_security_issues(self, result: Dict[str, Any]) -> List[str]:
        """
        Collect non-vulnerability security issues.

        Args:
            result: Scan result dictionary

        Returns:
            List of security issue descriptions
        """
        issues = []

        if result.get('xmlrpc_enabled'):
            issues.append(f"{self.ISSUE_EMOJI['xmlrpc']} XML-RPC is enabled")

        if result.get('user_registration_enabled'):
            issues.append(f"{self.ISSUE_EMOJI['user_registration']} User registration is enabled")

        directory_listings = result.get('directory_listings', [])
        if directory_listings:
            issues.append(f"{self.ISSUE_EMOJI['directory_listing']} {len(directory_listings)} directory listing(s) enabled")

        return issues

    def _determine_overall_severity(self, result: Dict[str, Any]) -> str:
        """
        Determine overall severity level for a scan result.

        Args:
            result: Scan result dictionary

        Returns:
            Severity level string
        """
        all_vulns = []

        all_vulns.extend(result.get('wordpress_vulnerabilities', []))

        for plugin in result.get('plugins', []):
            all_vulns.extend(plugin.get('vulnerabilities', []))

        for theme in result.get('themes', []):
            all_vulns.extend(theme.get('vulnerabilities', []))

        if not all_vulns:
            return 'info'

        # Find highest severity
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        for severity in severity_order:
            if any(v.get('severity', '').lower() == severity for v in all_vulns):
                return severity

        return 'medium'

    def _get_most_severe_vulnerability(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get the most severe vulnerability from a list.

        Args:
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            Most severe vulnerability
        """
        if not vulnerabilities:
            return {}

        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

        return min(
            vulnerabilities,
            key=lambda v: severity_order.get(v.get('severity', 'low').lower(), 5)
        )

    def _has_vulnerabilities(self, result: Dict[str, Any]) -> bool:
        """
        Check if a scan result has any vulnerabilities.

        Args:
            result: Scan result dictionary

        Returns:
            True if vulnerabilities are present
        """
        wp_vulns = len(result.get('wordpress_vulnerabilities', []))
        plugin_vulns = sum(p.get('vulnerability_count', 0) for p in result.get('plugins', []))
        theme_vulns = sum(t.get('vulnerability_count', 0) for t in result.get('themes', []))

        return (wp_vulns + plugin_vulns + theme_vulns) > 0

    def _send_message(self, payload: Dict[str, Any]) -> bool:
        """
        Send message to Slack webhook.

        Args:
            payload: Slack message payload

        Returns:
            True if message was sent successfully
        """
        try:
            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            if response.status_code == 200:
                return True
            else:
                return False

        except Exception:
            return False
