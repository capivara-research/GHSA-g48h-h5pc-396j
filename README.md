# GHSA-g48h-h5pc-396j — LaraDashboard path traversal to arbitrary file deletion/write (RCE)

[Português do Brasil](README.pt-BR.md) · [Official advisory](https://github.com/laradashboard/laradashboard/security/advisories/GHSA-g48h-h5pc-396j)

Public research evidence and safe local-lab reproduction material for a path traversal vulnerability in LaraDashboard's core-upgrade backup handling.

## At a glance

| Field | Value |
|---|---|
| Product | LaraDashboard |
| Product repository | [`laradashboard/laradashboard`](https://github.com/laradashboard/laradashboard) |
| Affected versions | `>= 0.9.2, <= 1.2.2` |
| Tested revision | `9dc1335835701651aef3adcb3e885acecb32402c` |
| Weakness | CWE-22 |
| Severity | High — CVSS 3.1 `7.2` |
| CVSS vector | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| Required permission | `settings.edit` (non-Superadmin) |
| Advisory | `GHSA-g48h-h5pc-396j` |

## Summary

`CoreUpgradeController` and `BackupService` append the caller-controlled `backup_file` or `filename` value directly to the backup directory. They do not normalize the resulting path or verify that it remains inside `storage/app/core-backups`.

A non-Superadmin user holding the delegatable `settings.edit` permission can consequently:

1. delete files outside the backup directory with `../` traversal; and
2. restore an attacker-selected ZIP already present on disk, copying its contents into application directories such as `routes`, `app`, `config`, `bootstrap`, and `vendor`.

The second vector enables arbitrary file write and can lead to remote code execution.

## Root cause

### Technical targets

| Item | Value |
|---|---|
| Delete path | `app/Services/BackupService.php::deleteBackup()` |
| Restore path | `app/Http/Controllers/Backend/CoreUpgradeController.php::restore()` |
| Endpoints | Core-upgrade backup delete and `POST /admin/settings/core-upgrades/restore` |
| Attacker-controlled parameters | `filename` and `backup_file` |
| Validation | `DeleteBackupRequest` and `RestoreRequest` accept bounded strings but do not enforce a basename or path containment |

```php
public function deleteBackup(string $filename): bool
{
    $path = $this->backupPath . '/' . $filename;

    if (File::exists($path)) {
        return File::delete($path);
    }

    return false;
}
```

The restore path uses the same pattern:

```php
$backupPath = $this->backupService->getBackupPath() . '/' . $request->validated('backup_file');
```

Validation only requires a bounded string. Directory components are allowed and no resolved-path containment check is performed.

## Reproduction

The original coordinated disclosure reproduced both vectors end to end on a clean local installation with a custom role holding only `settings.view` and `settings.edit`.

The [`poc/`](poc/) directory contains:

- a non-invasive source verifier;
- a loopback-only HTTP canary-deletion PoC;
- the exact request shapes used during the original validation.

The HTTP PoC refuses non-loopback targets and requires `--execute`. Create a disposable canary outside the backup directory before using it. Do not target production systems.

## Impact

An affected installation permits a delegated settings operator to cross the application's intended permission and filesystem boundaries. Confirmed effects include arbitrary deletion outside the application tree and overwriting application code from an attacker-selected archive.

## Remediation

- Reject empty names and all names for which `basename($name) !== $name`.
- Resolve both the backup root and selected file with `realpath()`.
- Require the resolved file to begin with the canonical backup-directory path plus a directory separator.
- Apply the same centralized resolver to delete, restore, and download operations.
- Add a restrictive filename allowlist as defense in depth.

## Disclosure

Reported through GitHub Private Vulnerability Reporting and published by the project on 2026-08-30. Reporter credit: [capivara-research](https://github.com/capivara-research).

## References

- [LaraDashboard product repository](https://github.com/laradashboard/laradashboard)
- [Published GitHub Security Advisory](https://github.com/laradashboard/laradashboard/security/advisories/GHSA-g48h-h5pc-396j)
- [CWE-22](https://cwe.mitre.org/data/definitions/22.html)

## Legal and safety notice

Use this material only on systems you own or are explicitly authorized to test. The PoCs are intended for isolated, disposable lab environments.
