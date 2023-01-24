function Get-OrganizationalUnitPermission {
    <#
    .SYNOPSIS
        Get ACL permissions of Organizational Units
    .DESCRIPTION
        Returns custom objects showing ACL data from specified OUs.  Accepts array of OUs, and wildcards on Principals.
        If no identity specified, outputs all ACLs on OU.
    .PARAMETER Principals
        Principal to filter by on ACL - Accepts wildcards, however format is domain\principal
    .PARAMETER OrganizationalUnits
        Array of OUs to check ACLs.  Supports cross-domain lookups.
    .EXAMPLE
        Get-OrganizationalUnitPermission -Principals "*Enterprise Admin*" -OrganizationalUnits "OU=Users,DC=Fabrikam,DC=COMs"
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$Principals,

        [Parameter(Mandatory = $true)]
        [string[]]$OrganizationalUnits
    )
    
    If ($PSBoundParameters.ContainsKey("Principals")) {
        $escapedPrincipals = $Principals | ForEach-Object { [Regex]::Escape($_) }
        $regexReadyPrincipals = '^({0})$' -f ($escapedPrincipals -replace '\\\*', '.*' -join '|')
    } else {
        $regexReadyPrincipals = ""
    }
    
    foreach ($organizationalUnit in $OrganizationalUnits) {
        $domain = Split-DomainFromDistinguishedName -DistinguishedName $organizationalUnit
        $domainController = Get-ADDomain -Server $domain | Select-Object -ExpandProperty PDCEmulator
        
        try { 
            $returnedACLs = Invoke-Command -ComputerName $domainController -ErrorAction Stop -ScriptBlock {
                Import-Module ActiveDirectory
                (Get-Acl -Path "AD:\$($using:organizationalUnit)").access | Where-Object IdentityReference -Match $using:regexReadyPrincipals
            }
        } catch {
            Write-Error $_.Exception.Message
            Continue
        }

        foreach ($returnedACL in $returnedACLs) {

            New-Object -TypeName psobject -Property @{
                OrganizationalUnit = $organizationalUnit
                ActiveDirectoryRights = $returnedACL.ActiveDirectoryRights
                InheritanceType = $returnedACL.InheritanceType
                ObjectType = $returnedACL.ObjectType
                InheritedObjectType = $returnedACL.InheritedObjectType
                ObjectFlags = $returnedACL.ObjectFlags
                AccessControlType = $returnedACL.AccessControlType
                IdentityReference = $returnedACL.IdentityReference
                IsInherited = $returnedACL.IsInherited
                InheritanceFlags = $returnedACL.InheritanceFlags
                PropagationFlags = $returnedACL.PropagationFlags
            }
        }
    }
}

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
