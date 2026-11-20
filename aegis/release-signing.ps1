# Shared local development signing for Olympus and Aegis. No private key is stored with the source.
function Read-OlympusSigningPin([Microsoft.Win32.RegistryHive]$Hive) {
    $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey($Hive, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $registry.OpenSubKey('SOFTWARE\Olympus\ReleaseSigning')
        if ($null -eq $key) { return }
        try {
            $pin = $key.GetValue('CertificateSha256', $null)
            if ($pin -isnot [string] -or $pin -notmatch '\A[0-9a-fA-F]{64}\z') {
                throw 'The configured Olympus signing fingerprint must be a SHA-256 certificate fingerprint.'
            }
            return $pin.ToUpperInvariant()
        }
        finally { $key.Dispose() }
    }
    finally { $registry.Dispose() }
}

function Get-OlympusSigningPin {
    Read-OlympusSigningPin ([Microsoft.Win32.RegistryHive]::LocalMachine)
}

function Get-OlympusBuildSigningPin {
    $pin = Get-OlympusSigningPin
    if ($pin) { return $pin }
    Read-OlympusSigningPin ([Microsoft.Win32.RegistryHive]::CurrentUser)
}

function Get-OlympusCertificateFingerprint([Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Certificate.RawData)).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Get-OlympusBuildSigner([string]$Pin) {
    $certs = @(Get-ChildItem -LiteralPath 'Cert:\CurrentUser\My' -CodeSigningCert | Where-Object {
        (Get-OlympusCertificateFingerprint $_) -eq $Pin
    })
    if ($certs.Count -ne 1 -or -not $certs[0].HasPrivateKey -or $certs[0].NotAfter -le (Get-Date)) {
        throw 'The configured Olympus signing certificate and a valid private key must be available in your Windows Personal store.'
    }
    return $certs[0]
}

function Assert-OlympusArtifactSignature([string]$Path, [string]$Pin) {
    if ([string]::IsNullOrWhiteSpace($Pin)) { throw 'A certificate fingerprint is required to verify an Olympus release.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or $null -eq $signature.SignerCertificate) {
        throw "Invalid Authenticode signature on $Path ($($signature.Status))."
    }
    if ((Get-OlympusCertificateFingerprint $signature.SignerCertificate) -ne $Pin) {
        throw "Unexpected Authenticode signer on $Path."
    }
}

function Set-OlympusArtifactSignature([string]$Path, [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate, [string]$Pin) {
    if ((Get-OlympusCertificateFingerprint $Certificate) -ne $Pin) {
        throw 'The selected signing certificate does not match the Olympus release fingerprint.'
    }
    $result = Set-AuthenticodeSignature -LiteralPath $Path -Certificate $Certificate -HashAlgorithm SHA256 -IncludeChain Signer -ErrorAction Stop
    if ($result.Status -ne 'Valid') {
        throw "Could not sign $Path ($($result.Status)). $($result.StatusMessage)"
    }
    Assert-OlympusArtifactSignature $Path $Pin
}

