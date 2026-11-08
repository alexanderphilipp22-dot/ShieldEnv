# 1. RSA Keypair generieren
Write-Host "Generiere RSA-2048 Schlusselpaar..." -ForegroundColor Cyan
$rsa = [System.Security.Cryptography.RSA]::Create(2048)
$pubKey = [Convert]::ToBase64String($rsa.ExportSubjectPublicKeyInfo())
$privKey = [Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey())

# Private Key sicher lokal speichern
$privKey | Out-File -Encoding ascii -FilePath "priv_key.txt"
Write-Host "[OK] priv_key.txt lokal gespeichert (NICHT AUF GITHUB PUSHEN!)." -ForegroundColor Green

# 2. Public Key direkt in Core/Licensing.cs injizieren
$licensingPath = "Core/Licensing.cs"
if (Test-Path $licensingPath) {
    $content = Get-Content $licensingPath -Raw
    $updatedContent = $content -replace 'PublicKeySpkiBase64 = ".*?";', "PublicKeySpkiBase64 = `"$pubKey`";"
    Set-Content -Path $licensingPath -Value $updatedContent
    Write-Host "[OK] Public Key erfolgreich in Core/Licensing.cs injiziert." -ForegroundColor Green
} else {
    Write-Host "[WARNUNG] Core/Licensing.cs nicht gefunden!" -ForegroundColor Yellow
}

# 3. Git Initialisierung und Push
Write-Host "Initialisiere Git Repository und pushe zu GitHub..." -ForegroundColor Cyan
git init
git add .
git commit -m "feat: Release-ready ShieldEnv Core with RSA Licensing and AOT CI"
git branch -M main

git remote remove origin 2>$null
git remote add origin https://github.com/alexanderphilipp22-dot/ShieldEnv.git

git push -u origin main
Write-Host "[OK] Code erfolgreich auf GitHub gepusht!" -ForegroundColor Green