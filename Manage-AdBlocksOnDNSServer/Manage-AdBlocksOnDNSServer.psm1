
<#
.Synopsis
    Manage Windows 2016 DNS Server Query Policies to block well know ad servers.
    The purpose of which is to deny queries for well known advertisment and tracking services.
.Description
    Adds Domain Query policies to block well known advertisment and tracking hosts from https://pgl.yoyo.org/adservers/serverlist.php
.Example
    Add new Query Policies for IPv4 address from the Internet:
        Manage-AdBlocksOnDNSServer -DomainController dc-01 -ExecutionMode Interactive -Action Add -IPVersion IPv4 -AdDomainsSource Internet

    Add new Query Policies for IPv4 address from a new-line, or comma delimeted text file:
        Manage-AdBlocksOnDNSServer -DomainController dc-01 -ExecutionMode Interactive -Action Add -IPVersion IPv4 -AdDomainsSource Local -SourceFile C:\temp\bad-domains.txt

    Add new Query Policies for IPv4 address from a new-line, or comma delimeted text file:
        Manage-AdBlocksOnDNSServer -DomainController dc-01 -ExecutionMode Interactive -Action Add -IPVersion IPv4 -AdDomainsSource CommandLine -AdDomains doubleclick.com,googleadservices.com


    Remove query policies from the server for all domains returned:
        Manage-AdBlocksOnDNSServer -DomainController dc-02 -ExecutionMode Interactive -Action Remove -IPVersion IPv4 -AdDomainsSource Internet
    Remove query policies from the server for a specific domain by substring:
        Manage-AdBlocksOnDNSServer -DomainController dc-02 -ExecutionMode Interactive -IPVersion IPv4 -AdDomainsSource CommandLine -AdServerDomain google -Action Remove

    Verify that the policy for the given domain, or domain substing, exists, but do not return the object:
        Manage-AdBlocksOnDNSServer -DomainController dc-01 -ExecutionMode Interactive -IPVersion IPv6 -AdDomainsSource CommandLine -AdServerDomain google -Action Check
    Return the DNS Server Policy Object for the given domain, or domain substring:
        Manage-AdBlocksOnDNSServer -DomainController dc-01 -ExecutionMode Interactive -IPVersion IPv4 -AdDomainsSource CommandLine -AdServerDomain google -Action Get

.Outputs

.Notes
     MODULE: Microsoft.PowerShell.Profile
     AUTHOR: Matthew A. R. Sherian <msherian@marsys-llc>
#>
function Manage-AdBlocksOnDNSServer {
    [cmdletbinding()]
    param
    (
        [parameter(Mandatory=$false)]  [ValidateSet('Interactive','Unattended')] $ExecutionMode,
        [parameter(Mandatory=$true)]  $DomainController,
        [parameter(Mandatory=$true)]  [ValidateSet('Add','Remove','Get','Check','Update','Flush')] $Action,
        [parameter(Mandatory=$false)]  [ValidateSet('IPv4','IPv6')] $IPVersion,
        [parameter(Mandatory=$false)] $AdServerDomain,
        [parameter(Mandatory=$false)] [ValidateSet('Internet','Local','CommandLine')]$AdDomainsSource,
        [parameter(Mandatory=$false)] $SourceFile
        )
    $PSDefaultParameterValues["Manage-AdBlocksOnDNSServer:ExecutionMode"]="Interactive"
    $PSDefaultParameterValues["Manage-AdBlocksOnDNSServer:AdDomainsSource"]="Internet"
    $PSDefaultParameterValues["Manage-AdBlocksOnDNSServer:IPversion"]="IPv4"


    $DomainController=(Resolve-DnsName $DomainController|Select-Object -Property Name -Unique).Name.ToLower()

    Switch ($IPVersion)
    {
        IPv4 { $QType="EQ,A" }
        IPv6 { $QType="EQ,AAAA"}
    }
    $private:i=1

    Switch ($AdDomainsSource)
    {
        Internet
        {
            if (!$AdDomains)
            {
                $global:AdDomains = ((curl 'https://pgl.yoyo.org/adservers/serverlist.php?hostformat=plain;showintro=0').Content.Split("`n") |?{$_ -notmatch "<|>" -and $_ -match ".+" }) -split "`n"
            }
        }
        Local
        {
            if (!$AdDomains)
            {
                if ($SourceFile)
                {
                    $global:AdDomains = (Get-Content $SourceFile).Split(",|`n")
                }else{
                    Write-ColorOutput -stdout:$true -type fail -text "When using the parameter 'Local'  the parameter 'SourceFile' is required"
                }
            }
        }
        CommandLine
        {
            if (!$AdDomains)
            {
                if ($AdServerDomain)
                {
                    $global:AdDomains = ($AdServerDomain).Split(",|`n")
                }else{
                    Write-ColorOutput -stdout:$true -type fail -text "When using the parameter 'CommandLine'  the parameter 'AdServerDomain' is required"
                }
            }
        }
    }

    if ($AdServerDomain){ $AdDomains=$AdDomains |Select-String -SimpleMatch $AdServerDomain }
    $local:tot=$AdDomains.Count
    $AdDomains | `
    %{
        $i++
        $fqdn=$_
        if ($ExecutionMode -eq "Unattended")
        {
            $progressPreference="SilentlyContinue"
        }
        Write-Progress -Activity "On $DomainController performing action: $Action on $i/$tot domains" -Status "Processing $fqdn"
        Switch ($Action)
        {
            Add    #Attempts to add regardless of the existence of a matching policy, errors are suppressed.
            {
                try
                {
                    Add-DnsServerQueryResolutionPolicy -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true) -Debug:($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true) -ea SilentlyContinue -ComputerName $DomainController -Name "$IPVersion Block ADs for $fqdn" -action deny -fqdn "EQ,*.$fqdn" -QType $QType
                }
                catch { }
                if ($error[0] -notmatch $fqdn )
                {
                    Write-ColorOutput -stdout:$true -type ok -text "Added $IPVersion Policy Entry for $fqdn"
                }
            }
            Remove
            {
            Get-DnsServerQueryResolutionPolicy -ea Ignore -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true) -Debug:($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true) -ComputerName $DomainController  |? Name -match "$IPVersion Block ADs for $fqdn" |`
            %{
                    $polObj=$_
                    if ($polObj)
                    {
                        try
                        {
                            $polObj|Remove-DnsServerQueryResolutionPolicy -ea Ignore -ComputerName $DomainController -Confirm:$false -Force -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true) -Debug:($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true)
                        }
                        catch
                        { }
                        if ($error[0] -notmatch $fqdn )
                        {
                            Write-ColorOutput -stdout:$true -type warn -text "Removed Policy Entry $($polObj.Name) for $fqdn"
                        }
                    }else{
                        Write-ColorOutput -stdout:$true -type fail -text "Policy Entry Not Found for $fqdn"
                    }
                }
            }
            Check
            {
                $private:_this=Get-DnsServerQueryResolutionPolicy -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true) -Debug:($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true) -ComputerName $DomainController |? Name -match "$IPVersion Block ADs for $fqdn" -ea Ignore
                if ($private:_this)
                {
                    Write-ColorOutput -stdout:$true -type ok -text "$DomainController has a policy for $fqdn"
                }else{
                    Write-ColorOutput -stdout:$true -type fail -text "$DomainController lacks a policy for $fqdn"
                }

            }
			Get
			{
				Get-DnsServerQueryResolutionPolicy -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true) -Debug:($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true) -ComputerName $DomainController |? Name -match "$IPVersion Block ADs for $fqdn" -ea Ignore
			}
            Update #Checks for Domains and then adds.
            {
                $_this=Manage-AdBlocksOnDNSServer -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true) -Debug:($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true)-DomainController $DomainController -IPVersion $IPVersion -Action Get -AdServerDomain $fqdn -AdDomainsSource CommandLine
                if (!($_this))
                {
                    Manage-AdBlocksOnDNSServer -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true) -Debug:($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true) -DomainController $DomainController -IPVersion $IPVersion  -AdDomainsSource CommandLine -Action Add -AdServerDomain $fqdn
                }
            }
            Flush
            {
                $remove=Get-DnsServerQueryResolutionPolicy -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true) -Debug:($PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent -eq $true) -ComputerName $DomainController
                $remove | Remove-DnsServerQueryResolutionPolicy -ComputerName $DomainController -Confirm:$False -Force
            }
        }
    }
    Remove-Variable -ea SilentlyContinue -Scope Global AdDomains
}
function Write-ColorOutput{
param(
                [parameter(Mandatory=$true)]
                [ValidateSet('ok','warn','fail')]    $type,
                [parameter(Mandatory=$true, ValueFromPipeline=$true)] $text,
                $stdout
                
)
                $ofg=$host.ui.RawUI.ForegroundColor
                switch ($type){
                                "ok"   {$host.ui.RawUI.ForegroundColor="Green"}
                                "warn" {$host.ui.RawUI.ForegroundColor="Yellow"}
                                "fail" {$host.ui.RawUI.ForegroundColor="Red"}
                }
                
                if ($stdout){ Write-Host $text }else {Write-Output $text}
                $host.ui.RawUI.ForegroundColor=$ofg
}

Export-ModuleMember -Function Manage-AdBlocksOnDNSServer