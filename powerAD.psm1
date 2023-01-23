function Get-RecursiveGroupMembers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Identity
    )


    results = @()

    foreach ($group in $Identity) {
        

        $groupDomain = Split-DomainFromDistinguishedName -DistinguishedName $Identity

        try {
            $groupObject = Get-ADGroup -Identity $group -Server $groupDomain -Properties Member
        } catch {
            $_.Exception
            Continue
        }

        


    }
}


function Split-DomainFromDistinguishedName {
    <#
    .SYNOPSIS
        Returns domain name from Distinsuished Name
    .DESCRIPTION
        Returns domain name from Distinguished Name
    .PARAMETER DistinguishedName
        Distinguished Name you would like to split
    .PARAMETER SecondLevelDomain
        Force second level domain output
    .EXAMPLE
        Split-DomainFromDistinguishedName -DistinguishedName "CN=Litware,OU=Docs\, Adatum,DC=Fabrikam,DC=COMs"
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$DistinguishedName,

        [Parameter()]
        [switch]$SecondLevelDomain
    )

    if ($PSBoundParameters.ContainsKey('SecondLevelDomain')) {
        (($DistinguishedName -split ',DC=')[-2..-1] -join '.').toLower() 
    } else {
        (($DistinguishedName -split ',DC=')[1..(($DistinguishedName -split ',DC=').count - 1)] -join '.').toLower()
    }
}
