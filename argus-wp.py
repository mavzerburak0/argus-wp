#!/usr/bin/env python3
"""
Command-line interface for WordPress vulnerability scanner.
"""
import sys
import click

from src.core.config import (
    ScanConfig,
    ScanMode,
    OutputFormat,
    EnumerationTarget
)
from src.core.scanner import WordPressScanner


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    Argus-WP - WordPress Vulnerability Scanner

    A comprehensive security scanner for WordPress installations.
    """
    pass


@cli.command()
@click.argument('url', required=False)
@click.option(
    '--targets', '-t',
    type=click.Path(exists=True),
    help='File containing list of URLs to scan (one per line)'
)
@click.option(
    '--urls',
    multiple=True,
    help='Multiple URLs to scan (can be used multiple times)'
)
@click.option(
    '--enumerate', '-e',
    multiple=True,
    type=click.Choice(['p', 't', 'all'], case_sensitive=False),
    default=['p', 't'],
    help='Enumerate plugins (p), themes (t), or all'
)
@click.option(
    '--threads',
    type=int,
    default=5,
    help='Number of threads (default: 5)'
)
@click.option(
    '--timeout',
    type=int,
    default=10,
    help='Request timeout in seconds (default: 10)'
)
@click.option(
    '--random-agent',
    is_flag=True,
    help='Use random User-Agent strings'
)
@click.option(
    '--user-agent',
    type=str,
    help='Custom User-Agent string'
)
@click.option(
    '--proxy',
    type=str,
    help='Proxy URL (e.g., http://127.0.0.1:8080)'
)
@click.option(
    '--output', '-o',
    type=click.Path(),
    help='Output file path'
)
@click.option(
    '--format', '-f',
    type=click.Choice(['cli', 'json'], case_sensitive=False),
    default='cli',
    help='Output format (default: cli)'
)
@click.option(
    '--verbose', '-v',
    is_flag=True,
    help='Verbose output'
)
@click.option(
    '--debug',
    is_flag=True,
    help='Debug output'
)
@click.option(
    '--no-color',
    is_flag=True,
    help='Disable colored output'
)
@click.option(
    '--mode',
    type=click.Choice(['passive', 'normal', 'aggressive', 'stealth'], case_sensitive=False),
    default='normal',
    help='Scan mode (default: normal)'
)
@click.option(
    '--rate-limit',
    type=float,
    default=0.0,
    help='Delay between requests in seconds (default: 0)'
)
@click.option(
    '--no-ssl-verify',
    is_flag=True,
    help='Disable SSL certificate verification'
)
@click.option(
    '--slack-webhook',
    type=str,
    help='Slack webhook URL for sending scan results notifications'
)
def scan(
    url: str,
    targets: str,
    urls: tuple,
    enumerate: tuple,
    threads: int,
    timeout: int,
    random_agent: bool,
    user_agent: str,
    proxy: str,
    output: str,
    format: str,
    verbose: bool,
    debug: bool,
    no_color: bool,
    mode: str,
    rate_limit: float,
    no_ssl_verify: bool,
    slack_webhook: str
):
    """
    Scan WordPress site(s) for vulnerabilities.

    URL: Single target WordPress site URL

    Examples:

      argus-wp scan https://example.com

      argus-wp scan https://example.com --enumerate p,t --verbose

      argus-wp scan --urls https://site1.com --urls https://site2.com

      argus-wp scan --targets urls.txt -o results.json -f json
    """
    # Collect all target URLs
    target_urls = []

    if url:
        target_urls.append(url)

    if urls:
        target_urls.extend(urls)

    if targets:
        # Read URLs from file
        try:
            with open(targets, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        target_urls.append(line)
        except Exception as e:
            click.echo(f"Error reading targets file: {e}", err=True)
            sys.exit(1)

    if not target_urls:
        click.echo("Error: No target URL(s) provided. Use URL argument, --urls, or --targets option.", err=True)
        sys.exit(1)

    # Remove duplicates while preserving order
    seen = set()
    unique_urls = []
    for target_url in target_urls:
        if target_url not in seen:
            seen.add(target_url)
            unique_urls.append(target_url)

    target_urls = unique_urls

    # If multiple targets, scan them all
    if len(target_urls) > 1:
        _scan_multiple_targets(
            target_urls, enumerate, threads, timeout,
            random_agent, user_agent, proxy, output, format, verbose,
            debug, no_color, mode, rate_limit, no_ssl_verify, slack_webhook
        )
        return

    # Single target - use existing logic
    url = target_urls[0]
    # Convert enumerate tuple to set of EnumerationTarget
    enumerate_targets = set()
    for e in enumerate:
        if e.lower() == 'p':
            enumerate_targets.add(EnumerationTarget.PLUGINS)
        elif e.lower() == 't':
            enumerate_targets.add(EnumerationTarget.THEMES)
        elif e.lower() == 'all':
            enumerate_targets.add(EnumerationTarget.ALL)

    # Convert mode string to ScanMode enum
    scan_mode = ScanMode[mode.upper()]

    # Convert format string to OutputFormat enum
    output_format = OutputFormat[format.upper()]

    # Create scan configuration
    config = ScanConfig(
        target_url=url,
        enumerate=enumerate_targets,
        scan_mode=scan_mode,
        threads=threads,
        timeout=timeout,
        user_agent=user_agent,
        random_agent=random_agent,
        proxy=proxy,
        output_format=output_format,
        output_file=output,
        verbose=verbose,
        debug=debug,
        no_color=no_color,
        rate_limit=rate_limit,
        verify_ssl=not no_ssl_verify
    )

    try:
        # Initialize scanner
        scanner = WordPressScanner(config)

        # Run scan
        result = scanner.scan()

        # Export results if output file is specified
        if output:
            export_results(result, output, output_format)
            click.echo(f"\n[+] Results exported to: {output}")

        # Send to Slack if webhook is configured
        if slack_webhook:
            _send_to_slack(result, slack_webhook, verbose)

        # Exit with appropriate code
        if result.get_total_vulnerabilities() > 0:
            sys.exit(1)  # Vulnerabilities found
        else:
            sys.exit(0)  # No vulnerabilities

    except KeyboardInterrupt:
        click.echo("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        click.echo(f"\n[-] Error: {str(e)}", err=True)
        if debug:
            raise
        sys.exit(1)


def _scan_multiple_targets(
    target_urls, enumerate, threads, timeout,
    random_agent, user_agent, proxy, output, format, verbose,
    debug, no_color, mode, rate_limit, no_ssl_verify, slack_webhook
):
    """
    Scan multiple WordPress targets.

    Args:
        target_urls: List of URLs to scan
        ... (other scan parameters)
    """
    import json
    from datetime import datetime

    click.echo(f"\n[*] Starting batch scan of {len(target_urls)} target(s)")
    click.echo(f"[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    all_results = []
    successful_scans = 0
    failed_scans = 0

    # Use builtins.enumerate to avoid conflict with enumerate parameter
    import builtins
    for idx, target_url in builtins.enumerate(target_urls, 1):
        click.echo(f"\n{'='*60}")
        click.echo(f"[*] Scanning target {idx}/{len(target_urls)}: {target_url}")
        click.echo(f"{'='*60}\n")

        # Convert enumerate tuple to set of EnumerationTarget
        enumerate_targets = set()
        for e in enumerate:
            if e.lower() == 'p':
                enumerate_targets.add(EnumerationTarget.PLUGINS)
            elif e.lower() == 't':
                enumerate_targets.add(EnumerationTarget.THEMES)
            elif e.lower() == 'all':
                enumerate_targets.add(EnumerationTarget.ALL)

        # Convert mode string to ScanMode enum
        scan_mode = ScanMode[mode.upper()]

        # Convert format string to OutputFormat enum
        output_format = OutputFormat[format.upper()]

        # Create scan configuration
        config = ScanConfig(
            target_url=target_url,
            enumerate=enumerate_targets,
            scan_mode=scan_mode,
            threads=threads,
            timeout=timeout,
            user_agent=user_agent,
            random_agent=random_agent,
            proxy=proxy,
            output_format=output_format,
            output_file=None,  # Don't write individual files
            verbose=verbose,
            debug=debug,
            no_color=no_color,
            rate_limit=rate_limit,
            verify_ssl=not no_ssl_verify
        )

        try:
            # Initialize scanner
            scanner = WordPressScanner(config)

            # Run scan
            result = scanner.scan()
            all_results.append(result.to_dict())
            successful_scans += 1

            # Send to Slack immediately after each scan if webhook is configured
            if slack_webhook:
                _send_to_slack(result, slack_webhook, verbose, is_batch=False)

        except KeyboardInterrupt:
            click.echo("\n[!] Batch scan interrupted by user")
            break
        except Exception as e:
            click.echo(f"\n[-] Error scanning {target_url}: {str(e)}", err=True)
            failed_scans += 1
            if debug:
                raise

    # Display summary
    click.echo(f"\n\n{'='*60}")
    click.echo("BATCH SCAN SUMMARY")
    click.echo(f"{'='*60}")
    click.echo(f"Total targets: {len(target_urls)}")
    click.echo(f"Successful scans: {successful_scans}")
    click.echo(f"Failed scans: {failed_scans}")
    click.echo(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Calculate total vulnerabilities across all targets
    total_vulns = 0
    vulnerable_sites = 0
    for result in all_results:
        vulns = (len(result.get('wordpress_vulnerabilities', [])) +
                result.get('plugin_vulnerabilities', 0) +
                result.get('theme_vulnerabilities', 0))
        total_vulns += vulns
        if vulns > 0:
            vulnerable_sites += 1

    click.echo(f"Total vulnerabilities found: {total_vulns}")
    click.echo(f"Vulnerable sites: {vulnerable_sites}/{successful_scans}")

    # Export consolidated results if output file is specified
    if output and all_results:
        output_format = OutputFormat[format.upper()]
        if output_format == OutputFormat.JSON:
            consolidated = {
                'scan_summary': {
                    'total_targets': len(target_urls),
                    'successful_scans': successful_scans,
                    'failed_scans': failed_scans,
                    'total_vulnerabilities': total_vulns,
                    'vulnerable_sites': vulnerable_sites,
                    'scan_timestamp': datetime.now().isoformat()
                },
                'results': all_results
            }
            with open(output, 'w') as f:
                json.dump(consolidated, f, indent=2)
            click.echo(f"\n[+] Consolidated results exported to: {output}")
        else:
            click.echo("\n[!] Only JSON format is supported for batch scans")

    # Note: Individual Slack messages are sent after each scan completes
    # No batch summary message is sent to avoid duplication

    # Exit with appropriate code
    if total_vulns > 0:
        sys.exit(1)  # Vulnerabilities found
    else:
        sys.exit(0)  # No vulnerabilities


def export_results(result, output_file: str, format: OutputFormat):
    """
    Export scan results to file.

    Args:
        result: ScanResult object
        output_file: Output file path
        format: Output format
    """
    if format == OutputFormat.JSON:
        import json
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
    elif format == OutputFormat.XML:
        click.echo("[!] XML export not yet implemented")
    elif format == OutputFormat.HTML:
        click.echo("[!] HTML export not yet implemented")
    elif format == OutputFormat.CSV:
        click.echo("[!] CSV export not yet implemented")
    else:
        click.echo("[!] Unsupported export format")


def _send_to_slack(data, webhook_url: str, verbose: bool, is_batch: bool = False):
    """
    Send scan results to Slack webhook.

    Args:
        data: Scan result data (ScanResult object or dict for batch)
        webhook_url: Slack webhook URL
        verbose: Verbose output flag
        is_batch: Whether this is a batch scan result
    """
    try:
        from src.utils.slack_notifier import SlackNotifier

        if verbose:
            click.echo("\n[*] Sending results to Slack...")

        notifier = SlackNotifier(webhook_url)

        # Convert ScanResult to dict if needed
        if hasattr(data, 'to_dict'):
            scan_data = data.to_dict()
        else:
            scan_data = data

        success = notifier.send_scan_results(scan_data, is_batch=is_batch)

        if success:
            click.echo("[+] Results successfully sent to Slack")
        else:
            click.echo("[-] Failed to send results to Slack", err=True)

    except Exception as e:
        click.echo(f"[-] Error sending to Slack: {str(e)}", err=True)


if __name__ == '__main__':
    cli()
