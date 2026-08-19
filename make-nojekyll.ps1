# Creates .nojekyll for GitHub Pages (Windows hides dotfiles in many upload UIs).
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dest = Join-Path $here ".nojekyll"
"" | Out-File -FilePath $dest -Encoding ascii -NoNewline
Write-Host "Created: $dest"
Write-Host "Commit and push, or rename dot-nojekyll.upload-me to .nojekyll on GitHub."
