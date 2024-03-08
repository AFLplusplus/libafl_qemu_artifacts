cd /d "H:\LibaflNtfsFuzz" &msbuild "LibaflNtfsFuzz.vcxproj" /t:sdvViewer /p:configuration="Debug" /p:platform="x64" /p:SolutionDir="H:\LibaflNtfsFuzz" 
exit %errorlevel% 