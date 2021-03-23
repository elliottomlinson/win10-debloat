# Reclaiming Disk Space From Windows 10

A fresh install of Windows 10 20H2 took up more than 63GB on my machine. I was able to cut that down to ~10GB by:

#### 1. Removing hiberfil.sys

Issued `powercfg /h off` as admin to disable hibernation completely.

#### 2. Shrinking pagefil.sys

`Start > View advanced system settings > Performance Settings > Advanced > Virtual Memory`
Uncheck `Automatic management` and set initial as` 800 MB` and max as `2000 MB` as per
https://www.techradar.com/how-to/how-to-delete-move-and-resize-pagefilesys.

#### 3. Disabling Windows Auto-Update

Launched `gpedit.msc` and navigated to `Local Group Police Editor > Computer Configuration > Administrative Templates > Windows Components > Windows Update` and disabled it in the right-hand panel.

#### 4. Deleting Unnecessary Windows SoftwareDistribution Files

Only after Windows Updates are complete. Open `cmd.exe` as admin and issue `net stop wuauserv` and `net stop bits` then manually delete the contents of `%WINDIR%\SoftwareDistribution`.

#### 5. Removing Unnecessary Proprietary MOBO Software

My mobo seems to have a dedicated cache for fan/OC/LED settings beyond what you can change in the BIOS since the profile I set with a windows program persisted through windows uninstallation, ubuntu installation, win reinstallation.  I tweaked the profiles and then removed the software manually from `C:\Program Files,` `C:\Program Files (x86)`, and `AppData\Local` by deleting the ASUS folders and reg entries. The profile data has once again persisted.

#### 6. Uninstalling Non-Essential Programs

Uninstalled everything except graphics driver from `Start > Control Panel > Programs > Uninstall`.

#### 7. Uninstalling OneDrive

Disabled `Settings > Windows Security > Ransomware Protection` Then unlinked the PC by clicking through the OneDrive Taskbar Menus: `Icon > User Image > Unlink this PC > Unlink account`. Then quit the program from the taskbar. After reading about some reinstall sneaks I also made sure to:
- `Taskmgr > Startup > Disable win defender icon`
- `Settings > Sync > Sync settings off`
- `Settings > Automatic file downloads off`
- `regedit > HKEY_CLASSES_ROOT CLSID {018D5C66-4533-4307-9B53-224DE2ED1FE6}` change `System.IsPinnedToSpaceTree` to 0

Then deleted the OneDrive Folder from the start menu and removed the pin from Quick Access in File Explorer,
then uninstalled it from `Start > Control Panel > Programs > Programs and Features`.

#### 8. Removing MS Software Reinstall Sneaks

Disabled all from `Task Manager > Startup`.

#### 9. Removing (Some) Cortana Reinstall Sneaks

Right click the taskbar
- Check `Hidden` under Search
- Hide everything in that section (i.e. `Task View Button`)
- Lock the Taskbar

#### 10. Accounting for Other Misc. Windows Sneaks

Disabled everything in `Start > Privacy`.

#### 11. Uninstalling Optional Features

Unchecked all except notepad and powershell from `Start > Manage Optional Features`.

#### 12. Removing Internet Explorer Files That Survived Optional Feature Removal

Run`Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 –Online` as admin, then reboot.

#### 13. Clearing Some But Probably Not All Windows Temp Files and Caches

`Start > Disk Cleanup`.

#### 14. Removing Nvidia Software After Nvoluntary Nstallation

Uninstalled from Programs. Kept Nvidia control panel.

#### 15. Uninstalling Uninstalled Program Residuals

Manually deleted residual files and folders from `C:\Program Files`, `C:\Program Files (x86)`, and `AppData\*`.

#### 16. Disabling Windows Reserved Storage

run `Set-WindowsReservedStorageState -State disabled` as admin in PowerShell, then run `regedit.exe` and navigate to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager`. Change `ShippedWithReserves` to 0 and reboot.

#### 17. Clearing WinSxS Bloat

Run these as admin to remove old versions of windows components:
`DISM.exe /online /Cleanup-Image /StartComponentCleanup`
`DISM.exe /online /Cleanup-Image /SPSuperseded`
`DISM.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase`

#### 18. Automatically cleaning Up .DS_Store, Thumbs.db, Windows Defender, Unused Reg Keys

Used Bleachbit Portable.

#### 19. Automatically Deleting Windows Log Files

Used CCleaner Portable as Admin.

#### 20. Deleting Temporary Appdata

Deleted all contents manually after bleachbit and CCleaner left some behind.

#### 21. Deleting Windows Prefetch Data

Required manual deletion from `C:\Windows\Prefetch`.

#### 22. Deleting Windows Temp Files Exempted from Bleachbit

Manually deleted from `C:\ProgramData\Microsoft\Windows\WER\Temp`.

#### 23. Not Removing Old Defender Updates

wontfix, defender needs them and I am not interested in other antivirus software.

#### 24. Uninstalling Unnecessary Drivers

https://github.com/lostindark/DriverStoreExplorer/releases/tag/v0.11.64
found several ASUS drivers for gamer gear to uninstall.

#### 25. More Windows Temp Files

Navigate to `Settings > System > Storage > Configure Storage Sense`, check all temp files and run.

#### 26. Emptying the Recycle Bin

Empty the recycle bin.

#### 27. Reindexing OS Search

`Settings > Search > Searching Windows > More Search Indexer Settings > Advanced Search Indexer Settings > Advanced`
`Index Settings > Troubleshooting > Rebuild` then click OK.

#### 28. Compressing Windows OS Files

Run `Compact.exe /CompactOS:always` as admin after doing everything else. I got a few GB back and a faster boot time.

