from __future__ import annotations

import os
import pwd
import re
import stat
import subprocess
from pathlib import Path
from typing import Any


def run_command(command: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def check_root_accounts() -> dict[str, Any]:
    findings = []

    try:
        root_accounts = [
            entry
            for entry in pwd.getpwall()
            if entry.pw_uid == 0
        ]
    except Exception as exc:
        return {
            "check": "root_accounts",
            "status": "WARN",
            "severity": "medium",
            "message": f"Unable to inspect passwd database: {exc}",
        }

    names = [entry.pw_name for entry in root_accounts]

    if names == ["root"]:
        findings.append({
            "status": "PASS",
            "severity": "info",
            "message": "Only the root account has UID 0.",
        })
    else:
        findings.append({
            "status": "WARN",
            "severity": "high",
            "message": (
                "Multiple UID 0 accounts detected: "
                + ", ".join(names)
            ),
        })

    return {
        "check": "root_accounts",
        "findings": findings,
    }


def check_listening_ports() -> dict[str, Any]:
    return_code, stdout, stderr = run_command(
        ["ss", "-tuln"]
    )

    if return_code != 0:
        return {
            "check": "listening_ports",
            "findings": [{
                "status": "WARN",
                "severity": "medium",
                "message": (
                    f"Unable to inspect listening ports: "
                    f"{stderr or 'ss command unavailable'}"
                ),
            }],
        }

    lines = [
        line
        for line in stdout.splitlines()
        if line and not line.startswith("Netid")
    ]

    ports = []

    for line in lines:
        match = re.search(
            r":(\d+)\s*$",
            line,
        )

        if match:
            port = int(match.group(1))
            if port not in ports:
                ports.append(port)

    findings = []

    if not ports:
        findings.append({
            "status": "PASS",
            "severity": "info",
            "message": "No listening TCP/UDP ports were detected.",
        })
    else:
        for port in sorted(ports):
            if port in {22, 80, 443}:
                severity = "low"
                status = "INFO"
                message = f"Expected/common service port {port} is listening."
            elif port < 1024:
                severity = "medium"
                status = "WARN"
                message = f"Privileged port {port} is listening."
            else:
                severity = "low"
                status = "WARN"
                message = f"Non-standard port {port} is listening."

            findings.append({
                "status": status,
                "severity": severity,
                "message": message,
                "port": port,
            })

    return {
        "check": "listening_ports",
        "findings": findings,
    }


def check_services() -> dict[str, Any]:
    return_code, stdout, stderr = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--no-legend",
        ]
    )

    if return_code != 0:
        return {
            "check": "running_services",
            "findings": [{
                "status": "WARN",
                "severity": "low",
                "message": (
                    f"Unable to inspect system services: "
                    f"{stderr or 'systemctl unavailable'}"
                ),
            }],
        }

    services = [
        line.split()[0]
        for line in stdout.splitlines()
        if line.strip()
    ]

    findings = [{
        "status": "INFO",
        "severity": "info",
        "message": f"{len(services)} system services are currently running.",
        "count": len(services),
        "services": services,
    }]

    return {
        "check": "running_services",
        "findings": findings,
    }


def parse_ssh_value(lines: list[str], key: str) -> str | None:
    for line in lines:
        clean = line.strip()

        if not clean or clean.startswith("#"):
            continue

        parts = clean.split(None, 1)

        if len(parts) == 2 and parts[0].lower() == key.lower():
            return parts[1].strip()

    return None


def check_ssh_config() -> dict[str, Any]:
    ssh_config = Path("/etc/ssh/sshd_config")

    if not ssh_config.exists():
        return {
            "check": "ssh_configuration",
            "findings": [{
                "status": "INFO",
                "severity": "info",
                "message": "/etc/ssh/sshd_config was not found; SSH server may not be installed.",
            }],
        }

    try:
        lines = ssh_config.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines()
    except OSError as exc:
        return {
            "check": "ssh_configuration",
            "findings": [{
                "status": "WARN",
                "severity": "medium",
                "message": f"Unable to read SSH configuration: {exc}",
            }],
        }

    findings = []

    permit_root = parse_ssh_value(
        lines,
        "PermitRootLogin",
    )

    password_auth = parse_ssh_value(
        lines,
        "PasswordAuthentication",
    )

    if permit_root and permit_root.lower() in {
        "yes",
        "prohibit-password",
        "without-password",
    }:
        findings.append({
            "status": "WARN",
            "severity": "high",
            "message": f"SSH root login is configured as '{permit_root}'.",
        })
    else:
        findings.append({
            "status": "PASS",
            "severity": "info",
            "message": "SSH root login is restricted or disabled.",
        })

    if password_auth and password_auth.lower() == "yes":
        findings.append({
            "status": "WARN",
            "severity": "medium",
            "message": "SSH password authentication is enabled.",
        })
    else:
        findings.append({
            "status": "PASS",
            "severity": "info",
            "message": "SSH password authentication is disabled or not explicitly enabled.",
        })

    return {
        "check": "ssh_configuration",
        "findings": findings,
    }


def permission_bits(path: Path) -> str | None:
    try:
        return stat.filemode(path.stat().st_mode)
    except OSError:
        return None


def check_sensitive_permissions() -> dict[str, Any]:
    targets = [
        (
            Path("/etc/passwd"),
            stat.S_IRUSR
            | stat.S_IWUSR
            | stat.S_IRGRP
            | stat.S_IROTH,
        ),
        (
            Path("/etc/shadow"),
            stat.S_IRUSR
            | stat.S_IWUSR,
        ),
        (
            Path("/etc/group"),
            stat.S_IRUSR
            | stat.S_IWUSR
            | stat.S_IRGRP
            | stat.S_IROTH,
        ),
    ]

    findings = []

    for path, allowed_bits in targets:
        try:
            mode = path.stat().st_mode
        except OSError as exc:
            findings.append({
                "status": "WARN",
                "severity": "medium",
                "message": f"Unable to inspect {path}: {exc}",
            })
            continue

        actual_bits = stat.S_IMODE(mode)
        display_mode = permission_bits(path)

        if path.name == "shadow":
            safe = actual_bits & (
                stat.S_IRWXG
                | stat.S_IRWXO
            ) == 0
        else:
            safe = (
                actual_bits
                & ~allowed_bits
            ) == 0

        if safe:
            findings.append({
                "status": "PASS",
                "severity": "info",
                "message": f"{path} has permissions {display_mode}.",
            })
        else:
            findings.append({
                "status": "WARN",
                "severity": "high",
                "message": f"{path} has potentially unsafe permissions {display_mode}.",
            })

    return {
        "check": "sensitive_file_permissions",
        "findings": findings,
    }


def check_firewall() -> dict[str, Any]:
    checks = [
        (
            ["ufw", "status"],
            "UFW",
        ),
        (
            ["firewall-cmd", "--state"],
            "firewalld",
        ),
    ]

    for command, name in checks:
        return_code, stdout, _ = run_command(command)

        if return_code != 0:
            continue

        output = stdout.lower()

        if "active" in output or "running" in output:
            return {
                "check": "firewall",
                "findings": [{
                    "status": "PASS",
                    "severity": "info",
                    "message": f"{name} firewall appears to be active.",
                }],
            }

        if "inactive" in output or "not running" in output:
            return {
                "check": "firewall",
                "findings": [{
                    "status": "WARN",
                    "severity": "high",
                    "message": f"{name} firewall appears to be inactive.",
                }],
            }

    return {
        "check": "firewall",
        "findings": [{
            "status": "INFO",
            "severity": "medium",
            "message": "No supported active firewall manager was detected.",
        }],
    }


def run_all_checks() -> list[dict[str, Any]]:
    return [
        check_root_accounts(),
        check_listening_ports(),
        check_services(),
        check_ssh_config(),
        check_sensitive_permissions(),
        check_firewall(),
    ]
