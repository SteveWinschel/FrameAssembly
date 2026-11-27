# PowerShell tab completion for frameassembly (FrameAssembly v3.3.1)
# https://github.com/SteveWinschel/FrameAssembly

Register-ArgumentCompleter -Native -CommandName frameassembly -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $subcommands = @(
        @{ Name = 'show';    Description = 'Inspect a .frasm file or .pcap/.pcapng capture (or - for stdin) as a packet ladder' }
        @{ Name = 'reverse'; Description = 'Reverse a .pcap or .pcapng capture (or - for stdin) into .frasm code' }
        @{ Name = 'update';  Description = 'Update frameassembly to the newest release' }
        @{ Name = 'version'; Description = 'Print the FrameAssembly version' }
        @{ Name = 'help';    Description = 'Print help for FrameAssembly or a subcommand' }
    )

    $elements = $commandAst.CommandElements
    $argIndex = if ([string]::IsNullOrEmpty($wordToComplete)) {
        $elements.Count
    } else {
        $elements.Count - 1
    }

    function Complete-FilteredPaths([string]$Prefix, [string[]]$Extensions) {
        $searchPattern = "${Prefix}*"
        Get-ChildItem -Path $searchPattern -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSIsContainer) {
                $dirVal = Join-Path $_.DirectoryName $_.Name
                if (-not $Prefix.Contains([IO.Path]::DirectorySeparatorChar) -and -not $Prefix.Contains('/')) {
                    $dirVal = $_.Name
                }
                $sep = [IO.Path]::DirectorySeparatorChar
                [System.Management.Automation.CompletionResult]::new(
                    "${dirVal}${sep}",
                    "${dirVal}${sep}",
                    'ProviderContainer',
                    $_.FullName
                )
            } elseif ($Extensions -contains $_.Extension.ToLowerInvariant()) {
                $fileVal = if ($Prefix.Contains([IO.Path]::DirectorySeparatorChar) -or $Prefix.Contains('/')) {
                    $_.FullName
                } else {
                    $_.Name
                }
                [System.Management.Automation.CompletionResult]::new(
                    $fileVal,
                    $_.Name,
                    'ProviderItem',
                    $_.FullName
                )
            }
        }
    }

    function Complete-StdioDash([string]$Prefix, [string]$Description) {
        if ($Prefix -eq '-') {
            [System.Management.Automation.CompletionResult]::new('-', '-', 'ParameterValue', $Description)
        }
    }

    if ($argIndex -eq 1) {
        foreach ($sc in $subcommands) {
            if ($sc.Name -like "${wordToComplete}*") {
                [System.Management.Automation.CompletionResult]::new(
                    $sc.Name,
                    $sc.Name,
                    'ParameterValue',
                    $sc.Description
                )
            }
        }
        Complete-StdioDash $wordToComplete 'Read .frasm code from stdin'
        Complete-FilteredPaths $wordToComplete @('.frasm')
        return
    }

    $sub = $elements[1].Extent.Text
    switch ($sub) {
        'show' {
            if ($argIndex -eq 2) {
                Complete-StdioDash $wordToComplete 'Read .frasm or capture from stdin'
                Complete-FilteredPaths $wordToComplete @('.frasm', '.pcap', '.pcapng')
            }
        }
        'reverse' {
            if ($argIndex -eq 2) {
                Complete-StdioDash $wordToComplete 'Read capture from stdin'
                Complete-FilteredPaths $wordToComplete @('.pcap', '.pcapng')
            } elseif ($argIndex -eq 3) {
                Complete-StdioDash $wordToComplete 'Write .frasm code to stdout'
                Complete-FilteredPaths $wordToComplete @('.frasm')
            }
        }
        'help' {
            if ($argIndex -eq 2) {
                foreach ($sc in $subcommands) {
                    if ($sc.Name -like "${wordToComplete}*") {
                        [System.Management.Automation.CompletionResult]::new(
                            $sc.Name,
                            $sc.Name,
                            'ParameterValue',
                            $sc.Description
                        )
                    }
                }
            }
        }
        'update' {
        }
        'version' {
        }
        default {
            if (($sub -eq '-' -or -not $sub.StartsWith('-')) -and $argIndex -eq 2) {
                Complete-StdioDash $wordToComplete 'Write PCAPNG capture to stdout'
                Complete-FilteredPaths $wordToComplete @('.pcap', '.pcapng')
            }
        }
    }
}
