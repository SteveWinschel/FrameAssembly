# PowerShell tab completion for frameassembly
# https://github.com/SteveWinschel/FrameAssembly

Register-ArgumentCompleter -Native -CommandName frameassembly -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $subcommands = @(
        @{ Name = 'show';    Description = 'Validate a .fasm file and print its packet ladder table' }
        @{ Name = 'reverse'; Description = 'Reverse a .pcap or .pcapng capture into .fasm code' }
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
        Complete-FilteredPaths $wordToComplete @('.fasm')
        return
    }

    $sub = $elements[1].Extent.Text
    switch ($sub) {
        'show' {
            if ($argIndex -eq 2) { Complete-FilteredPaths $wordToComplete @('.fasm') }
        }
        'reverse' {
            if ($argIndex -eq 2) { Complete-FilteredPaths $wordToComplete @('.pcap', '.pcapng') }
            elseif ($argIndex -eq 3) { Complete-FilteredPaths $wordToComplete @('.fasm') }
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
        'version' {
        }
        default {
            if (-not $sub.StartsWith('-') -and $argIndex -eq 2) {
                Complete-FilteredPaths $wordToComplete @('.pcap', '.pcapng')
            }
        }
    }
}
