function Get-RecursiveGroupMembers {
    <#
    .SYNOPSIS
        Returns recursive list of group membership including containing group name
    .DESCRIPTION
        Returns recursive list of group membership including containing group name
    .PARAMETER Identity
        Distinguished Name of group
    .EXAMPLE
        Get-RecursiveGroupMembers -Identity "CN=Litware,OU=Docs\, Adatum,DC=Fabrikam,DC=COMs"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$Identity
    )

    $results = @()

    foreach ($group in $Identity) {
        
        $groupDomain = Split-DomainFromDistinguishedName -DistinguishedName $group

        try {
            $groupObject = Get-ADGroup -Identity $group -Server $groupDomain -Properties Member
        } catch {
            $_.Exception
            Continue
        }

        foreach ($member in $groupObject.Member) {
            $memberDomain = Split-DomainFromDistinguishedName -DistinguishedName $member
            $adObject = Get-ADObject -Identity $member -Server $memberDomain
            $results += New-Object -TypeName psobject -Property @{
                Member = (Get-ADObject -Identity $adObject.DistinguishedName -Server $memberDomain)
                DirectGroup = $group
            }

            if ($adObject.ObjectClass -eq "group") {
                $nestedGroups = Get-RecursiveGroupMembers -Identity $adObject.DistinguishedName
                $results += $nestedGroups
            }       
        }
        return $results
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
