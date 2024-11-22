# Successful signin from foreign country

### Alert Details:

#### Explanation:&#x20;

This alert trigers when a user upload a file that contains file extensions of an executable (.exe, .cmd, .bat...) to Office services (Onedrive, Teams, etc...)

#### Impact:&#x20;

* Lateral mouvement attack through cloud services (Teams, Sharepoint...)

### IOCs and valuable infos:

* Files uploaded
*

### Queries used:

```plsql
let KnownCountries = SigninLogs
  | where TimeGenerated > ago(90d) and TimeGenerated < ago(3d)
    | where ResultType == 0
    | where isnotempty(Location)
    | distinct Location;
SigninLogs
| where TimeGenerated > ago(3d)
| where ResultType == 0
| where isnotempty(Location)
| where Location !in (KnownCountries)
| project TimeGenerated, Location, UserAgent, ResultType, Identity, UserPrincipalName, IPAddress
```



### Actions taken to mitigate the threat:

