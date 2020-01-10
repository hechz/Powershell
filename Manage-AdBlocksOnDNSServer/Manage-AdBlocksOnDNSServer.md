---
external help file: Manage-AdBlocksOnDNSServer-help.xml
Module Name: Manage-AdBlocksOnDNSServer
online version:
schema: 2.0.0
---

# Manage-AdBlocksOnDNSServer

## SYNOPSIS
Manage Windows 2016 DNS Server Query Policies to block well know ad servers.
The purpose of which is to deny queries for well known advertisment and tracking services.

## SYNTAX

```
Manage-AdBlocksOnDNSServer [[-ExecutionMode] <Object>] [-DomainController] <Object> [-Action] <Object>
 [[-IPVersion] <Object>] [[-AdServerDomain] <Object>] [[-AdDomainsSource] <Object>] [[-SourceFile] <Object>]
 [<CommonParameters>]
```

## DESCRIPTION
Adds Domain Query policies to block well known advertisment and tracking hosts from https://pgl.yoyo.org/adservers/serverlist.php

## EXAMPLES

### EXAMPLE 1
```
Add new Query Policies for IPv4 address from the Internet:
```

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

## PARAMETERS

### -ExecutionMode
{{ Fill ExecutionMode Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -DomainController
{{ Fill DomainController Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Action
{{ Fill Action Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -IPVersion
{{ Fill IPVersion Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AdServerDomain
{{ Fill AdServerDomain Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AdDomainsSource
{{ Fill AdDomainsSource Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SourceFile
{{ Fill SourceFile Description }}

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
MODULE: Microsoft.PowerShell.Profile
AUTHOR: Matthew A.
R.
Sherian \<msherian@marsys-llc\>

## RELATED LINKS
