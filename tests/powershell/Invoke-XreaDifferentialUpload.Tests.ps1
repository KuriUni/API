BeforeAll {
    . (Join-Path $PSScriptRoot '..\..\operations\Xrea\Invoke-XreaDifferentialUpload.ps1')
    $script:OriginalLocalAppData = $env:LOCALAPPDATA
    $env:LOCALAPPDATA = $TestDrive
}

AfterAll {
    $env:LOCALAPPDATA = $script:OriginalLocalAppData
}

Describe 'XREA differential upload state' {
    It 'persists state as valid UTF-8 JSON and reuses it only for identical content' {
        $source = Join-Path $TestDrive 'source'
        New-Item -ItemType Directory -Path $source -Force | Out-Null
        $file = Join-Path $source 'health.txt'
        [System.IO.File]::WriteAllText($file, 'stable-content')

        $plan = Get-XreaDifferentialPlan -LocalRoot $source -StateKey 'test-state'
        $plan.Changed.Count | Should -Be 1

        Save-XreaDifferentialState -State @{ 'health.txt' = $plan.Changed[0].Hash } -StateFile $plan.StateFile
        $secondPlan = Get-XreaDifferentialPlan -LocalRoot $source -StateKey 'test-state'
        $secondPlan.Changed.Count | Should -Be 0

        $json = Get-Content -LiteralPath $plan.StateFile -Raw | ConvertFrom-Json
        $json.'health.txt' | Should -Be $plan.Changed[0].Hash
    }

    It 'fails closed when another process holds the destination lock' {
        $stateKey = 'test-concurrent-lock'
        $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($stateKey)
        $hasher = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = $hasher.ComputeHash($keyBytes)
            $stateName = (($hash | ForEach-Object { $_.ToString('x2') }) -join '') + '.json'
        } finally { $hasher.Dispose() }

        $stateRoot = Join-Path $env:LOCALAPPDATA 'XreaDeploy\sync-state'
        New-Item -ItemType Directory -Path $stateRoot -Force | Out-Null
        $lockPath = Join-Path $stateRoot ($stateName + '.lock')
        $heldLock = [System.IO.File]::Open(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
        try {
            { Invoke-XreaDifferentialUpload -Session ([pscustomobject]@{}) -LocalRoot $TestDrive -RemoteRoot '/test' -StateKey $stateKey -TransferOptions ([pscustomobject]@{}) } | Should -Throw '*Another deployment is using this destination/state key*'
        } finally {
            $heldLock.Dispose()
        }
    }
}
