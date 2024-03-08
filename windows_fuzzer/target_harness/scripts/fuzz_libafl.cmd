SET RAMDISK_DRIVE=V:
SET RAMDISK_SIZE=512M
SET RAMDISK_LABEL=RAMDISK

:ramdisk
if not exist "%RAMDISK_DRIVE%" (
"%PROGRAMFILES%\OSFMount\OSFMount.com" -a -t vm -s %RAMDISK_SIZE% -o format:fat32:"%RAMDISK_LABEL%" -m "%RAMDISK_DRIVE%
if not errorlevel 1 goto fuzz
goto ramdisk
)

:fuzz
"F:\LibaflNtfsFuzz_libafl.exe"

