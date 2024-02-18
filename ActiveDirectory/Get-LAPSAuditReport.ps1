#@{Name="Title";Expression={[string]$_.Title}},@{Name="KB Article";Expression={[string]::join(' | ',$_.KnowledgebaseArticles[0])}},

$Events = (Get-WinEvent -FilterHashtable @{ LogName='Security'; Id='4662'; StartTime=$((Get-Date).AddHours(-1)) } | Where-Object { $_.Message -like "*f3531ec6-6330-4f8e-8d39-7a671fbac605*" } )

$Results = @()
ForEach ($Event in $Events) {
    [XML]$XMLEvent = $Event.ToXml()
#    $Event.TimeCreated
#    $(($XMLEvent.Event.EventData.Data | ? { $_.Name -like "SubjectUserName"}).'#text')
$(($XMLEvent.Event.EventData.Data | ? { $_.Name -like "SubjectUserName"}).'#text')
    $Results += [PSCustomObject]@{
        'TimeCreated' = $Event.TimeCreated
        'SubjectUserName'  = $(($XMLEvent.Event.EventData.Data | ? { $_.Name -like "SubjectUserName"}).'#text')
        'MachineName' = $Event.MachineName
        'KeywordsDisplayNames' = $Event.KeywordsDisplayNames
        'Computer' = $XMLEvent.Event.System.Computer
    }
}
$Results | ft -AutoSize

<# .Event.EventData.data

Name              #text
----              -----
SubjectUserSid    S-1-5-18
SubjectUserName   DC01$
SubjectDomainName lapsifh
SubjectLogonId    0x1e78212
ObjectServer      DS
ObjectType        %{bf967a86-0de6-11d0-a285-00aa003049e2}
ObjectName        %{c9064d61-1d2b-46f0-b9ca-b4d5b35249c7}
OperationType     Object Access
HandleId          0x0
AccessList        %%7688...
AccessMask        0x100
Properties        %%7688...
AdditionalInfo    -
AdditionalInfo2
#>