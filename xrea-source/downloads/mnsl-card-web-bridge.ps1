# MNSL local card-key bridge for the TUTI reception web flow.
# Windows PowerShell 7, 64-bit JPKI CSP, card reader, and card are required.
$ErrorActionPreference = 'Stop'
$Port = 17891
$AllowedOrigins = @('https://2415.jp', 'https://backup.2415.jp')

if (-not $IsWindows -or [IntPtr]::Size -ne 8) {
    throw 'このブリッジは64bit Windowsで実行してください。'
}

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public static class MNSLWebCardProof
{
    private const UInt32 PROV_RSA_AES = 24;
    private const UInt32 AT_SIGNATURE = 2;
    private const UInt32 KP_CERTIFICATE = 26;
    private const UInt32 CALG_SHA_256 = 0x0000800c;
    private const string ProviderName = "JPKI Crypto Service Provider for Auth";

    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CryptAcquireContextW(ref IntPtr provider, string container, string providerName, UInt32 providerType, UInt32 flags);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool CryptGetUserKey(IntPtr provider, UInt32 keySpec, out IntPtr key);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool CryptGetKeyParam(IntPtr key, UInt32 param, [Out] byte[] data, ref UInt32 dataBytes, UInt32 flags);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool CryptCreateHash(IntPtr provider, UInt32 algorithm, IntPtr key, UInt32 flags, out IntPtr hash);
    [DllImport("advapi32.dll", SetLastError=true)]
    private static extern bool CryptHashData(IntPtr hash, [In] byte[] data, UInt32 dataBytes, UInt32 flags);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CryptSignHashW(IntPtr hash, UInt32 keySpec, string description, UInt32 flags, [Out] byte[] signature, ref UInt32 signatureBytes);
    [DllImport("advapi32.dll")] private static extern bool CryptDestroyHash(IntPtr hash);
    [DllImport("advapi32.dll")] private static extern bool CryptDestroyKey(IntPtr key);
    [DllImport("advapi32.dll")] private static extern bool CryptReleaseContext(IntPtr provider, UInt32 flags);

    private static byte[] Der(byte tag, byte[] content)
    {
        byte[] length;
        if (content.Length < 128) length = new byte[] { (byte)content.Length };
        else
        {
            int n = content.Length, count = 0;
            while (n > 0) { count++; n >>= 8; }
            length = new byte[count + 1]; length[0] = (byte)(0x80 | count);
            n = content.Length;
            for (int i = count; i > 0; i--) { length[i] = (byte)(n & 0xff); n >>= 8; }
        }
        byte[] result = new byte[1 + length.Length + content.Length];
        result[0] = tag; Buffer.BlockCopy(length, 0, result, 1, length.Length); Buffer.BlockCopy(content, 0, result, 1 + length.Length, content.Length);
        return result;
    }

    private static byte[] DerInteger(byte[] value)
    {
        int first = 0; while (first < value.Length - 1 && value[first] == 0) first++;
        byte[] normalized = new byte[value.Length - first]; Buffer.BlockCopy(value, first, normalized, 0, normalized.Length);
        if ((normalized[0] & 0x80) != 0) { byte[] padded = new byte[normalized.Length + 1]; Buffer.BlockCopy(normalized, 0, padded, 1, normalized.Length); normalized = padded; }
        return Der(0x02, normalized);
    }

    private static byte[] SubjectPublicKeyInfo(RSAParameters parameters)
    {
        byte[] rsaKey = Der(0x30, Combine(DerInteger(parameters.Modulus), DerInteger(parameters.Exponent)));
        byte[] algorithm = new byte[] { 0x30,0x0d,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01,0x05,0x00 };
        byte[] bitString = new byte[rsaKey.Length + 1]; Buffer.BlockCopy(rsaKey, 0, bitString, 1, rsaKey.Length);
        return Der(0x30, Combine(algorithm, Der(0x03, bitString)));
    }

    private static byte[] Combine(params byte[][] values)
    {
        int length = 0; foreach (byte[] value in values) length += value.Length;
        byte[] combined = new byte[length]; int offset = 0;
        foreach (byte[] value in values) { Buffer.BlockCopy(value, 0, combined, offset, value.Length); offset += value.Length; }
        return combined;
    }

    private static string Base64Url(byte[] value) { return Convert.ToBase64String(value).TrimEnd('=').Replace('+','-').Replace('/','_'); }
    private static Win32Exception Error(string message) { return new Win32Exception(Marshal.GetLastWin32Error(), message); }
    private static X509Certificate2 LoadCertificate(byte[] data)
    {
        Type loader = Type.GetType("System.Security.Cryptography.X509Certificates.X509CertificateLoader, System.Security.Cryptography.X509Certificates");
        if (loader != null)
        {
            var method = loader.GetMethod("LoadCertificate", new Type[] { typeof(byte[]) });
            if (method != null) return (X509Certificate2)method.Invoke(null, new object[] { data });
        }
        return (X509Certificate2)Activator.CreateInstance(typeof(X509Certificate2), new object[] { data });
    }

    // Returns signature and public SubjectPublicKeyInfo. No certificate, PIN, or private key leaves this process.
    public static string[] Sign(string message)
    {
        IntPtr provider = IntPtr.Zero, key = IntPtr.Zero, hash = IntPtr.Zero;
        byte[] certificateBytes = null, data = null, signature = null;
        try
        {
            if (!CryptAcquireContextW(ref provider, null, ProviderName, PROV_RSA_AES, 0))
                throw Error("JPKI認証用CSPを開けません。64bit CSP、カードリーダー、カードを確認してください。");
            if (!CryptGetUserKey(provider, AT_SIGNATURE, out key)) throw Error("JPKI認証用秘密鍵を取得できません。");
            UInt32 certificateLength = 0;
            if (!CryptGetKeyParam(key, KP_CERTIFICATE, null, ref certificateLength, 0) || certificateLength == 0 || certificateLength > 65536)
                throw Error("認証用証明書を読み取れません。");
            certificateBytes = new byte[certificateLength];
            if (!CryptGetKeyParam(key, KP_CERTIFICATE, certificateBytes, ref certificateLength, 0)) throw Error("認証用証明書を読み取れません。");
            using (X509Certificate2 certificate = LoadCertificate(certificateBytes))
            using (RSA rsa = certificate.GetRSAPublicKey())
            {
                if (rsa == null || rsa.KeySize < 2048 || rsa.KeySize > 4096) throw new CryptographicException("認証用公開鍵の形式に対応していません。");
                byte[] publicKey = SubjectPublicKeyInfo(rsa.ExportParameters(false));
                data = Encoding.UTF8.GetBytes(message);
                if (!CryptCreateHash(provider, CALG_SHA_256, IntPtr.Zero, 0, out hash)) throw Error("SHA-256ハッシュを作成できません。");
                if (!CryptHashData(hash, data, (UInt32)data.Length, 0)) throw Error("カード認証チャレンジをハッシュ化できません。");
                UInt32 signatureLength = 0;
                if (!CryptSignHashW(hash, AT_SIGNATURE, null, 0, null, ref signatureLength) || signatureLength < 256 || signatureLength > 1024)
                    throw Error("カード署名を準備できません。");
                signature = new byte[signatureLength];
                if (!CryptSignHashW(hash, AT_SIGNATURE, null, 0, signature, ref signatureLength)) throw Error("カード署名に失敗しました。");
                Array.Resize(ref signature, (int)signatureLength);
                Array.Reverse(signature); // CryptoAPI RSA signatures are little-endian; web/OpenSSL uses big-endian.
                return new string[] { Base64Url(signature), Base64Url(publicKey) };
            }
        }
        finally
        {
            if (signature != null) Array.Clear(signature, 0, signature.Length);
            if (data != null) Array.Clear(data, 0, data.Length);
            if (certificateBytes != null) Array.Clear(certificateBytes, 0, certificateBytes.Length);
            if (hash != IntPtr.Zero) CryptDestroyHash(hash);
            if (key != IntPtr.Zero) CryptDestroyKey(key);
            if (provider != IntPtr.Zero) CryptReleaseContext(provider, 0);
        }
    }
}
'@

function Send-BridgeResponse {
    param($Stream, [int]$Status, [string]$Body, [string]$Origin, [bool]$AllowCors, [bool]$PrivateNetwork)
    $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
    $reason = switch ($Status) { 200 {'OK'} 204 {'No Content'} 400 {'Bad Request'} 403 {'Forbidden'} 404 {'Not Found'} 405 {'Method Not Allowed'} 409 {'Conflict'} 500 {'Internal Server Error'} default {'OK'} }
    $headers = @("HTTP/1.1 $Status $reason",'Content-Type: application/json; charset=utf-8',"Content-Length: $($bytes.Length)",'Cache-Control: no-store','Connection: close','X-Content-Type-Options: nosniff')
    if ($AllowCors) {
        $headers += "Access-Control-Allow-Origin: $Origin"
        $headers += 'Vary: Origin'
        $headers += 'Access-Control-Allow-Methods: GET, POST, OPTIONS'
        $headers += 'Access-Control-Allow-Headers: Content-Type'
        if ($PrivateNetwork) { $headers += 'Access-Control-Allow-Private-Network: true' }
    }
    $head = [Text.Encoding]::ASCII.GetBytes(($headers -join "`r`n") + "`r`n`r`n")
    $Stream.Write($head,0,$head.Length)
    if ($bytes.Length -gt 0) { $Stream.Write($bytes,0,$bytes.Length) }
    $Stream.Flush()
}

function Read-HttpRequest {
    param($Stream)
    $headerBytes = [Collections.Generic.List[byte]]::new()
    $marker = [byte[]](13,10,13,10)
    while ($headerBytes.Count -lt 16384) {
        $one = $Stream.ReadByte()
        if ($one -lt 0) { throw 'request_closed' }
        $headerBytes.Add([byte]$one)
        $count = $headerBytes.Count
        if ($count -ge 4 -and $headerBytes[$count-4] -eq 13 -and $headerBytes[$count-3] -eq 10 -and $headerBytes[$count-2] -eq 13 -and $headerBytes[$count-1] -eq 10) { break }
    }
    if ($headerBytes.Count -ge 16384) { throw 'header_too_large' }
    $raw = [Text.Encoding]::ASCII.GetString($headerBytes.ToArray())
    $lines = $raw -split "`r`n"
    if ($lines.Count -lt 2 -or $lines[0] -notmatch '^(GET|POST|OPTIONS)\s+(\S+)\s+HTTP/1\.[01]$') { throw 'invalid_request_line' }
    $method = $matches[1]; $path = $matches[2]
    $headers = @{}
    foreach ($line in $lines[1..($lines.Count-1)]) {
        if ($line -match '^([^:]+):\s*(.*)$') { $headers[$matches[1].ToLowerInvariant()] = $matches[2].Trim() }
    }
    $length = 0
    if ($headers.ContainsKey('content-length')) { if (-not [int]::TryParse($headers['content-length'],[ref]$length) -or $length -lt 0 -or $length -gt 16384) { throw 'invalid_content_length' } }
    $body = New-Object byte[] $length
    $offset = 0
    while ($offset -lt $length) { $read = $Stream.Read($body,$offset,$length-$offset); if ($read -le 0) { throw 'request_body_incomplete' }; $offset += $read }
    return @{ Method=$method; Path=($path -split '\?')[0]; Headers=$headers; Body=[Text.Encoding]::UTF8.GetString($body) }
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,$Port)
$listener.Start()
Write-Host "MNSLカードWebブリッジを起動しました: http://127.0.0.1:$Port" -ForegroundColor Green
Write-Host '受付Web画面からの署名要求ごとに、このコンソールで確認します。終了するには Ctrl+C。' -ForegroundColor Yellow
try {
    while ($true) {
        $tcp = $listener.AcceptTcpClient()
        try {
            $stream = $tcp.GetStream(); $stream.ReadTimeout = 5000; $stream.WriteTimeout = 5000
            try { $request = Read-HttpRequest $stream } catch { Send-BridgeResponse $stream 400 '{"ok":false,"error":"invalid_request"}' '' $false $false; continue }
            $origin = [string]$request.Headers['origin']
            $allowedOrigin = $AllowedOrigins -contains $origin
            if (-not $allowedOrigin) { Send-BridgeResponse $stream 403 '{"ok":false,"error":"origin_not_allowed"}' '' $false $false; continue }
            $privateNetwork = ([string]$request.Headers['access-control-request-private-network']).ToLowerInvariant() -eq 'true'
            if ($request.Method -eq 'OPTIONS') { Send-BridgeResponse $stream 204 '' $origin $true $privateNetwork; continue }
            if ($request.Path -eq '/health' -and $request.Method -eq 'GET') {
                Send-BridgeResponse $stream 200 '{"ok":true,"bridge":"mnsl-card-web","version":"1.0.0"}' $origin $true $false
                continue
            }
            if ($request.Path -ne '/sign' -or $request.Method -ne 'POST') { Send-BridgeResponse $stream 404 '{"ok":false,"error":"not_found"}' $origin $true $false; continue }
            try { $payload = $request.Body | ConvertFrom-Json -AsHashtable -ErrorAction Stop } catch { Send-BridgeResponse $stream 400 '{"ok":false,"error":"invalid_json"}' $origin $true $false; continue }
            $flowId = [string]$payload.flow_id; $nonce = [string]$payload.nonce
            if ($flowId -notmatch '^[A-Za-z0-9_-]{43}$' -or $nonce -notmatch '^[A-Za-z0-9_-]{43}$') { Send-BridgeResponse $stream 400 '{"ok":false,"error":"invalid_challenge"}' $origin $true $false; continue }
            Write-Host "`n受付Web画面からカード署名要求 ($($flowId.Substring(0,8))) · $origin" -ForegroundColor Cyan
            $confirm = Read-Host 'カードを確認し、この1回の署名を許可する場合は Y を入力'
            if ($confirm -cne 'Y') { Send-BridgeResponse $stream 409 '{"ok":false,"error":"user_cancelled"}' $origin $true $false; continue }
            try {
                $message = "TUTI-MNSL-WEB-CARD-AUTH-V1`n$flowId`n$nonce"
                $proof = [MNSLWebCardProof]::Sign($message)
                $response = @{ ok=$true; signature=$proof[0]; public_key_spki=$proof[1] } | ConvertTo-Json -Compress
                Send-BridgeResponse $stream 200 $response $origin $true $false
            } catch {
                Write-Host "カード署名に失敗しました: $($_.Exception.Message)" -ForegroundColor Red
                Send-BridgeResponse $stream 500 '{"ok":false,"error":"card_sign_failed"}' $origin $true $false
            }
        } finally { $tcp.Dispose() }
    }
} finally { $listener.Stop() }
