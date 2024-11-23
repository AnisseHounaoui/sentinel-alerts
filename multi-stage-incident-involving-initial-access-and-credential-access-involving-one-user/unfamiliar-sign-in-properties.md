# Unfamiliar sign-in properties

### Alert Details:

#### Explanation:&#x20;

The alert comes from Microsoft Defender for Identity. It triggers when a sign-in property is not usually seen before compared to the baseline of the user's sign-in behaviour.

For example, if a user is used to login from a certain device and suddenly this time he sign-in from a different device. This is considered as an "unfamiliar" sign-in property. Since this sign-in doesn't align with his history sign-in patterns, It will trigger an alert.

This is a list of different sign-in properties that Defender checks for unfamiliarity:

* IP
* Location
* Device
* Browser
* ASN
* Tenant IP subnet

> **How does Defender really knows that a sign-in property is unfamiliar?**&#x20;
>
> When a user is created, he enters a "learning mode" period to define his sign-in baseline. During this period (minimum 5 days), this alert is disabled and the Machine Learning model learns the sign-in patterns of this user until it is capable of determining what sign-in properties lead to a risky sign-in.
>
> Once the model is capable of distinguishing between risky and not risky, the alert will be turned on
>
> P.S: a long period of inactivity, can reset the baseline and put the user back to "learning mode"&#x20;



#### Impact:&#x20;

* Lateral mouvement attack through cloud services (Teams, Sharepoint...)

### IOCs and valuable infos:

* Files uploaded
*

### Queries used:

```
// Some code
```



### Actions taken to mitigate the threat:



### Threat Huting

