# USB Guard for Windows

USB Guard is a Windows 11 x64 lab prototype that holds a removable volume until a malware scan finishes. A C minifilter denies file opens from ordinary Windows apps on a newly mounted removable disk. A C# Windows service reads the files and streams them to ClamAV. A WPF tray app shows progress and asks before moving flagged files off a drive.

**Lab scope.** Use Windows 11 24H2 or later and a single-partition FAT32 flash drive that Windows reports as removable. The filter attaches to disk volumes with the Windows removable-media flag. USB disks that report as fixed fall outside that boundary, while other media flagged removable can also be held. Windows still mounts the filesystem internally, and an Explorer drive letter may appear while opens are denied. The lab assumes a trusted Windows administrator, a single interactive user, and a driver already loaded before insertion. Previously opened handles, USB firmware or keyboard emulation, and post-release changes are outside the scan gate. The filter evaluates volumes independently. Approval lasts for one mounted volume instance.

## Build

1. On an x64 Windows development machine, install the .NET 10 SDK and a compatible Visual Studio, Windows SDK, and Windows Driver Kit. Use matching SDK and WDK versions. Open an x64 Visual Studio Developer PowerShell. [Windows Driver Kit](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk)
2. Build the desktop apps and the filter from the repo root.

   ```powershell
   .\scripts\Publish-Apps.ps1
   msbuild .\driver\UsbGuardFilter.vcxproj /p:Configuration=Debug /p:Platform=x64 /p:SignMode=TestSign
   ```

3. Locate the resulting package directory containing `UsbGuardFilter.inf`, `UsbGuardFilter.sys`, and `UsbGuardFilter.cat`. Use the WDK's test certificate on a dedicated lab machine or snapshot, and configure that machine to load test-signed drivers. The INF uses a lab altitude. A distributed driver needs its own Microsoft-assigned altitude and a production signature. [Test signing](https://learn.microsoft.com/windows-hardware/drivers/install/the-testsigning-boot-configuration-option) · [Minifilter altitudes](https://learn.microsoft.com/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)

## Set up the lab

Install the **x64 .NET 10 Desktop Runtime** on the test machine. The published service and tray use the installed runtime. If you built elsewhere, copy the repo scripts and both published app folders to the test machine, keeping the `artifacts\Service` and `artifacts\Tray` layout, along with the signed driver package. [Download .NET 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)

1. Install x64 ClamAV on the test machine. Copy [clamd.conf](scripts/clamd.conf) into its configuration directory. Set the same `DatabaseDirectory` in `clamd.conf` and `freshclam.conf`. Run `freshclam.exe` to download signatures. Run `clamd.exe --install-service` from the ClamAV install directory in an administrator shell. In Services, set the `clamd` account to **Local Service**, give it read access to the config and database, and start it. The configuration binds ClamAV to IPv4 loopback and rejects stale signatures at startup. USB Guard verifies the TCP connection belongs to the running `clamd` Windows service before sending files. [ClamAV Windows services](https://docs.clamav.net/manual/Usage/Services.html)
2. In Local Group Policy under **Computer Configuration → Administrative Templates → Windows Components → AutoPlay Policies**, enable **Turn off AutoPlay** for all drives and set **Set the default behavior for AutoRun** to **Do not execute any autorun commands**. Apply the policy before testing. [Microsoft AutoPlay policy](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-autoplay)
3. In an administrator PowerShell, with the test drives unplugged, install the lab package. Supply the INF from the built and signed package, next to its catalog and SYS file.

   ```powershell
   .\scripts\Install-Lab.ps1 -DriverInf 'C:\path\to\signed-package\UsbGuardFilter.inf'
   fltmc.exe filters
   Get-Service UsbGuard, clamd
   ```

4. Sign in to the standard test account and open `C:\Program Files\UsbGuard\Tray\UsbGuard.Tray.exe`. A local interactive user can view scan status and approve quarantine. Closing the window hides it to the tray. After a reboot, start `UsbGuardFilter` and `UsbGuard` from an administrator session before inserting test media. Both are configured for manual startup for the lab.

## Verify on Windows

Use two expendable FAT32 flash drives, one with ordinary files and one with the harmless [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/). Prepare both before loading the filter. After insertion, run `fltmc.exe instances -f UsbGuardFilter` from the administrator account to confirm the filter attached.

If another security product intercepts EICAR first, use a harmless binary fixture with a ClamAV-only test signature. On the lab machine, set `$database` to the configured ClamAV database directory and `$fixture` to a new `.bin` file on the test drive. Run these commands in an administrator shell before loading the filter. [ClamAV hash signatures](https://docs.clamav.net/manual/Signatures/HashSignatures.html)

```powershell
$bytes = New-Object byte[] 512
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
[IO.File]::WriteAllBytes($fixture, $bytes)
$hash = (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
"${hash}:512:UsbGuard.Lab.Test" | Set-Content (Join-Path $database 'usbguard-lab.hsb') -Encoding ascii
Restart-Service clamd
```

Unplug the test drive before loading the filter. Use the binary fixture for the detection cases below, then remove `usbguard-lab.hsb` from the database and restart `clamd` after the lab.

| Scenario | Expected result |
|---|---|
| ClamAV stopped, then insert an ordinary drive | The volume remains blocked. From the standard account, repeatedly try `Get-Content X:\sample.txt` using its actual drive letter. Check the volume GUID path as well. Start ClamAV and choose **Scan again**. The drive becomes accessible only after the scan completes. |
| Detection fixture, then choose **Keep drive blocked** | The finding appears in the tray and file opens remain denied. The original stays on the drive. |
| Detection fixture, then approve quarantine | The service copies and verifies each flagged file before removing the original by handle. After a complete rescan with no detections, the volume is released. Administrators can inspect the copy and its manifest in `C:\Program Files\UsbGuard\Service\Quarantine`. |
| Unplug during scanning or before approval, then insert another drive | The old approval cannot apply to the new volume. The replacement has its own scan and verdict. |
| Stop the USB Guard service with the filter loaded, then insert a new drive | The new volume remains blocked. Starting the service picks up the pending volume. |
| Insert a Windows-reported removable drive with an unsupported filesystem, an unreadable file, or a file larger than 64 MiB | The service reports an error and keeps access blocked. |

The scan walks hidden and system entries as well as ordinary files. It blocks on reported scanner errors, unreadable entries, or the configured scan limits. ClamAV signatures and supported file formats determine what the scan can detect. Quarantine may complete for some files before a later file fails. Completed copies remain protected, and the volume remains blocked until a later successful rescan. Keep original data backups for lab drives.

To remove the lab installation, unplug the test media, exit the tray app, run `Stop-Service UsbGuard` and `sc.exe delete UsbGuard` in an administrator shell, then run `fltmc.exe unload UsbGuardFilter`. Use `pnputil.exe /enum-drivers` to find the published INF matching `UsbGuardFilter.inf`, then `pnputil.exe /delete-driver oemNN.inf /uninstall` with that exact published name. The installation folder holds the quarantine copies. Preserve any copies you need before removing it.
