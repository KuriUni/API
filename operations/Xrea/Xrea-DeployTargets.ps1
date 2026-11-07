function Get-XreaDeployTargets {
    @(
        [pscustomobject]@{ Name = 'Primary'; Host = 's1004.xrea.com'; User = 'backup1tkmpc'; Remote = '/public_html/2415.jp/license' },
        [pscustomobject]@{ Name = 'Backup'; Host = 's1006.xrea.com'; User = 'tkm10pc4rds'; Remote = '/public_html/backup.2415.jp/license' }
    )
}
