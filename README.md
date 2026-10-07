# Pfn

RAMMap-style physical memory use from the command line. Pfn walks every
physical page on a Windows machine and reports what it is used for, which
paging list it is on, and, optionally, which files are holding it in the cache.

It reads the same Superfetch PFN data that Sysinternals
[RAMMap](https://learn.microsoft.com/sysinternals/downloads/rammap) shows in
its *Use Counts* and *File Summary* tabs, but prints plain text you can read in
a terminal, redirect, or export as CSV.

## Example

```text
> pfn -t -f
Scanning 200,973,792 pages (766.65 GiB) in 26 ranges... 100.0%
Resolving file names (kernel ETW file rundown)...

Use                       GiB
-----------------------------
Mapped File           666.552
Process Private        66.347
Metafile               11.570
System PTE              9.086
Paged Pool              7.679
Nonpaged Pool           4.043

List                      GiB
-----------------------------
Standby               673.756
Zeroed                 54.893
Active                 36.663
Modified                1.279

Total GiB    Active   Standby  Modified  File
------------------------------------------------------------------
   60.703     0.000    60.703     0.000  E:\video\movie-4k.mkv
   36.165     0.000    36.165     0.000  D:\vm\dev-disk.vhdx
   21.665     0.000    21.665     0.000  E:\models\qwen2.5-32b-instruct-q5_k_m.gguf
   ...
```

Without `-f`, Pfn prints only the two summary tables, with every category.

## Requirements

- Windows, 64-bit
- Administrator rights. If you start Pfn from a non-elevated prompt, it shows a
  UAC prompt and prints its output back in the same window.
- [.NET 10 SDK](https://dotnet.microsoft.com/download) to build

## Build

```powershell
git clone https://github.com/blakegordon/Pfn.git
cd Pfn
dotnet build -c Release
```

The executable is written to `bin\Release\net10.0-windows\Pfn.exe`.

## Usage

```text
Pfn [--csv=<file>] [--quiet] [--top] [--files [--all] [--most] [--debug]]
```

| Switch | Meaning |
| --- | --- |
| `--csv=<file>` | Also write the Use and List counts (and, with `--files`, every file) to a CSV file. |
| `-q`, `--quiet` | Print only the report, with no progress or status lines. |
| `-t`, `--top` | Omit categories under 1 GiB and sort each table by size, largest first. |
| `-f`, `--files` | List files with pages in RAM (Active, Standby, Modified), largest first. The list is cut to fit the console window unless `--all` is given or output is redirected. |
| `-a`, `--all` | List every file. Implies `--files`. |
| `-m`, `--most` | Like `--all`, but leave out files that would print as 0.000 GiB. Implies `--all`. |
| `-d`, `--debug` | Add a files-in-memory summary, ETW session statistics, and a breakdown of file objects that could not be named. Implies `--files`. |
| `-h`, `--help` | Show help. |

Status lines go to stderr and the report goes to stdout, so `pfn -f > report.txt`
captures just the report (every file, since the output is not a console).
Redirection only works from an elevated prompt: the UAC-elevated copy cannot
write to a redirect set up by a non-elevated shell, so Pfn stops with a message
instead.

Exit codes: `0` success, `1` elevation required or declined, `2` error.

## How it works

1. **Scan.** Pfn enables `SeProfileSingleProcessPrivilege`, asks
   `NtQuerySystemInformation(SystemSuperfetchInformation)` for the physical
   memory ranges, and then queries the PFN database for every page. Each page
   is counted by use (process private, mapped file, paged pool, ...) and by
   paging list (zeroed, free, standby, modified, active, ...).
2. **Name files (with `--files`).** For file-backed pages, the PFN data holds
   only a kernel file-object key. User mode cannot read a `FILE_OBJECT`, so Pfn
   starts a short-lived kernel ETW session with file-name tracing enabled and
   stops it. On stop, the kernel emits a *FileRundown* event for every file
   object it knows about, pairing each key with its
   `\Device\HarddiskVolumeN\...` path. Pfn matches keys to paths and converts
   them to drive-letter paths. Files on volumes without a drive letter (such as
   the EFI partition) keep their device path.

A full scan takes some time on machines with a lot of RAM; about 20 seconds
for 768 GiB, and a few seconds more with `--files`.

## Notes

- Pfn only reads memory-manager state. It does not change the cache or any
  paging list.
- Superfetch information classes are undocumented and may change between
  Windows releases.
- **Driver Locked** is where VirtualBox guest RAM appears when the VM uses
  native VT-x (HM), rather than as process private memory.
- Totals can differ slightly from run to run, because memory keeps changing
  while the scan runs.

## License

[MIT](LICENSE)
