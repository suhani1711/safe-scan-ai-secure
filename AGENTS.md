<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->
- Desktop app (desktop/, Electron) replaces the Chrome extension; site serves public/safescan-desktop.zip (source folder, zipped from desktop/ after edits). The one-click desktop install is the PWA (public/sw.js + public/manifest.webmanifest); the packaged Windows build (~184 MB) stays out of public/ — hand it over as a file instead.
