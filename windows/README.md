# Windows Live Response Collector

`IR_Response.ps1` is a PowerShell script that collects volatile and non-volatile forensic artifacts from a live Windows host.

## Run

```powershell
# Elevated PowerShell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\IR_Response.ps1
```

Requires Administrator (`#Requires -RunAsAdministrator`). Output folders (`volatile/`, `non_volatile/`) and the log, hash, and chain-of-custody files are created in the same directory as the script.

See the [top-level README](../README.md) for the full artifact list.
