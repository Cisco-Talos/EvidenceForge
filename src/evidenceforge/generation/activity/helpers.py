# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""General helper functions for activity generation.

Provides OS detection and command parameterization. RNG is re-exported
from evidenceforge.utils.rng for backward compatibility.
"""

from evidenceforge.utils.rng import _get_rng, _thread_local  # noqa: F401


def _get_os_category(os_string: str) -> str:
    """Detect OS category from OS string.

    Phase 2.10: OS-aware activity generation helper.

    Args:
        os_string: OS name/version (e.g., "Windows 10", "Linux Ubuntu 20.04")

    Returns:
        OS category: "windows", "linux", or "unknown"
    """
    os_lower = os_string.lower()
    if "windows" in os_lower:
        return "windows"
    elif (
        "linux" in os_lower
        or "ubuntu" in os_lower
        or "centos" in os_lower
        or "debian" in os_lower
        or "rhel" in os_lower
    ):
        return "linux"
    else:
        return "unknown"


# General parameterization pools for command-line diversification.
# Used across all process template categories, not just queries.
_GENERAL_PARAMS = {
    "project_path": [
        "C:\\Users\\{username}\\source\\repos\\webapp",
        "C:\\Users\\{username}\\source\\repos\\api-service",
        "C:\\Users\\{username}\\source\\repos\\internal-tools",
        "C:\\dev\\frontend",
        "C:\\dev\\microservices",
        "C:\\Users\\{username}\\projects\\analytics-dashboard",
    ],
    "source_file": [
        "Program.cs",
        "app.config",
        "index.ts",
        "main.py",
        "README.md",
        "Dockerfile",
        "appsettings.json",
        "webpack.config.js",
    ],
    "solution_name": [
        "WebApp.sln",
        "API.sln",
        "InternalTools.sln",
        "CoreServices.sln",
        "DataPipeline.sln",
    ],
    "build_config": ["Debug", "Release", "Staging"],
    "npm_script": ["build", "test", "lint", "start", "dev", "format", "ci"],
    "doc_path": [
        "Q4 Budget Review.docx",
        "Project Status Update.docx",
        "Meeting Notes - {username}.docx",
        "Architecture Decision Record.docx",
        "Sprint Retrospective.docx",
        "Vendor Proposal.docx",
    ],
    "spreadsheet_path": [
        "FY2024 Forecast.xlsx",
        "Resource Allocation.xlsx",
        "Inventory Report.xlsx",
        "KPI Dashboard.xlsx",
        "Budget vs Actuals.xlsx",
    ],
    "linux_project": [
        "/home/{username}/projects/api-server",
        "/home/{username}/projects/data-pipeline",
        "/home/{username}/src/monitoring",
        "/opt/company/webapp",
        "/home/{username}/repos/infra-config",
    ],
    "linux_source_file": [
        "main.py",
        "config.yaml",
        "server.go",
        "index.js",
        "Makefile",
        "deploy.sh",
        "requirements.txt",
    ],
    "git_branch": ["main", "develop", "feature/auth-refactor", "fix/memory-leak", "release/v2.4"],
    "internal_url": [
        "https://jira.corp.local/browse/PROJ-1234",
        "https://wiki.corp.local/display/ENG/Architecture",
        "https://gitlab.corp.local/team/project/-/pipelines",
        "https://grafana.corp.local/d/system-overview",
    ],
}

# Parameterized command-line value pools for process_query variety
_QUERY_PARAMS = {
    "db_server": ["localhost", "DB-SRV-01", "sqlprod01", "10.0.2.50", "SQLEXPRESS"],
    "db_name": ["master", "inventory", "analytics", "hr_records", "webapp_prod", "reporting"],
    "sql_query": [
        "SELECT TOP 100 * FROM dbo.Users ORDER BY LastLogin DESC",
        "SELECT COUNT(*) FROM dbo.Orders WHERE OrderDate > GETDATE()-7",
        "SELECT name, status FROM sys.databases",
        "EXEC sp_who2",
        "SELECT @@VERSION",
        "SELECT * FROM INFORMATION_SCHEMA.TABLES",
        "SELECT TOP 50 * FROM dbo.AuditLog ORDER BY EventTime DESC",
        "BACKUP DATABASE {db_name} TO DISK = N'D:\\Backups\\{db_name}.bak'",
        "SELECT name, recovery_model_desc FROM sys.databases",
        "DBCC CHECKDB ({db_name}) WITH NO_INFOMSGS",
    ],
    "ps_command": [
        "Get-EventLog -LogName Security -Newest 100",
        "Get-Process | Sort-Object CPU -Descending | Select-Object -First 20",
        'Get-Service | Where-Object {{$_.Status -eq \\"Running\\"}}',
        "Get-ADUser -Filter * -Properties LastLogonDate | Sort LastLogonDate",
        'Get-WinEvent -FilterHashtable @{{LogName=\\"System\\";Level=2}} -MaxEvents 50',
        "Test-NetConnection -ComputerName DC-01 -Port 389",
        "Get-ChildItem -Path C:\\Shares -Recurse | Measure-Object -Property Length -Sum",
        "Get-DnsServerZone | Format-Table -AutoSize",
        "Invoke-Command -ComputerName FILE-SRV-01 -ScriptBlock {{Get-Disk}}",
        'Get-ScheduledTask | Where-Object {{$_.State -ne \\"Disabled\\"}}',
    ],
    "ps_script": [
        "C:\\Scripts\\backup-check.ps1",
        "C:\\Scripts\\health-report.ps1",
        "C:\\Scripts\\disk-usage.ps1",
        "C:\\Scripts\\user-audit.ps1",
        "C:\\Admin\\update-inventory.ps1",
    ],
    "wmic_query": [
        "os get Caption,Version,OSArchitecture /format:list",
        "diskdrive get Size,Model,Status /format:list",
        "service where \"State='Running'\" get Name,ProcessId /format:csv",
        'process where "WorkingSetSize>100000000" get Name,ProcessId,WorkingSetSize',
        "cpu get LoadPercentage,NumberOfCores /format:list",
    ],
}

_QUERY_PARAMS_LINUX = {
    "mysql_db": ["wordpress", "inventory", "analytics", "appdb", "logging"],
    "mysql_query": [
        "SELECT COUNT(*) FROM sessions WHERE active=1",
        "SHOW PROCESSLIST",
        "SELECT table_name, table_rows FROM information_schema.tables WHERE table_schema='{db}'",
        "SHOW DATABASES",
        "SELECT * FROM wp_users LIMIT 10",
    ],
    "psql_db": ["postgres", "appdata", "metrics", "warehouse"],
    "redis_cmd": [
        "redis-cli INFO memory",
        "redis-cli DBSIZE",
        "redis-cli GET session:active_count",
        'redis-cli KEYS "cache:*" | head -20',
        "redis-cli MONITOR",
    ],
}


def _parameterize_command(rng, command_line: str, username: str = "") -> str:
    """Replace {placeholders} in command lines with random realistic values.

    Runs multiple passes since expanding one placeholder (e.g., {sql_query})
    may introduce new placeholders (e.g., {db_name} inside the query text).

    When username is provided, {username} is substituted first for per-user
    path customization. Per-user affinity is achieved by the caller seeding
    the rng appropriately.
    """
    # Substitute {username} first (literal, not random)
    if username and "{username}" in command_line:
        command_line = command_line.replace("{username}", username)

    all_params = {**_GENERAL_PARAMS, **_QUERY_PARAMS}
    for _pass in range(3):  # Max 3 passes to resolve nested placeholders
        changed = False
        for key, values in all_params.items():
            placeholder = "{" + key + "}"
            while placeholder in command_line:
                value = rng.choice(values)
                # Resolve {username} in chosen values too
                if username and "{username}" in value:
                    value = value.replace("{username}", username)
                command_line = command_line.replace(placeholder, value, 1)
                changed = True
        if not changed:
            break
    return command_line
