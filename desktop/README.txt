SafeScan AI Desktop - SOURCE (small version, ~100 KB)

This has every feature of the original app (floating shield, Links/SMS/Mail/QR scan,
Ctrl+Shift+Q snip QR, Ctrl+Shift+S scan selected text, dashboard, help, tray).
Only the 387 MB Electron runtime was removed - it is downloaded automatically when you build.

RUN IT:    install Node.js, then in this folder:   npm install   then   npm start
BUILD EXE: npm install   then   npm run build:win   -> dist/SafeScan-AI-win32-x64/SafeScan-AI.exe
NO PC?     Push this folder to GitHub; Actions > "Build Windows app" > Run workflow
           and download the finished zip from the run's Artifacts.
