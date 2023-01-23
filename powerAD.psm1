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

        foreach ($member in $groupObject.Member) {
            $memberDomain = Split-DomainFromDistinguishedName -DistinguishedName $member

            $adObject = Get-ADObject -Identity $member -Server $memberDomain

            if ($adObject.ObjectClass -eq "group") {
                $results += New-Object -TypeName psobject -Property @{
                    User = (Get-ADGroup -Identity $adObject.DistinguishedName -Server $memberDomain)
                    DirectGroup = $group
                }
                $nestedGroups = Get-RecursiveGroupMembers -Identity $adObject.DistinguishedName
                $results += $nestedGroups
            } elseif ($adObject.ObjectClass -eq "user") {
                $results += New-Object -TypeName psobject -Property @{
                    User = (Get-ADUser -Identity $adObject.DistinguishedName -Server $memberDomain)
                    DirectGroup = $group
                }
            } elseif ($adObject.ObjectClass -eq "msDS-GroupManagedServiceAccount") {
                $results += New-Object -TypeName psobject -Property @{
                    User = (Get-ADServiceAccount -Identity $adObject.DistinguishedName -Server $memberDomain)
                    DirectGroup = $group
                }
            } elseif ($adObject.ObjectClass -eq "computer") {
                $results += New-Object -TypeName psobject -Property @{
                    User = (Get-ADComputer -Identity $adObject.DistinguishedName -Server $memberDomain)
                    DirectGroup = $group
                }
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
