# Rare and potentially high-risk Office operations

### Alert Details:

#### Explanation:&#x20;

This alert trigers when a rare suspiciouss office operations occurs. These operations include 2 types:

* Mailbox operations:
  * New-Mailbox: create mailboxes and user accounts at the same time.
  * <mark style="background-color:red;">Set-Mailbox</mark>: modify the settings of existing mailboxes
  * Remove-Mailbox: delete mailboxes and the associated user accounts.
  *   Get-Mailbox: view mailbox objects and attributes, populate property pages, or supply mailbox information. Operation is privileged and can be used for enumerating users in an OU:

      ```powershell
      Get-Mailbox -OrganizationalUnit Users
      ```
* Inbox rules operations:
  *   <mark style="background-color:red;">New-InboxRule</mark> / <mark style="background-color:red;">Set-InboxRule</mark>:  <mark style="color:green;">New-InboxRule</mark> is used to create a new inbox rule to apply for email already there or future email.&#x20;

      <mark style="color:purple;">Set-InboxRule</mark> is to modify an existing inbox rule.&#x20;

      Both operations have the same parameters and most used onesfor these inbox rules:

      * #### -AlwaysDeleteOutlookRulesBlob <a href="#alwaysdeleteoutlookrulesblob" id="alwaysdeleteoutlookrulesblob"></a>
        * #### -BodyContainsWords <a href="#alwaysdeleteoutlookrulesblob" id="alwaysdeleteoutlookrulesblob"></a>
          * #### -CopyToFolder <a href="#bodycontainswords" id="bodycontainswords"></a>
          * -**ForwardTo**
          * **-SentTo**
  * <mark style="background-color:red;">Enable-InboxRule</mark>: enable a disabled inbox rule
  * Remove-InboxRule: delete the inbox rule permenantly
  * Disable-InboxRule: to disable an inbox rule (the disabled rule still exists but not active)



#### Impact ("T1114.003" , "T1098.002"):&#x20;

* Email Collection - Email Forwarding Rule (T1114.003) : Threat actors may setup email forwarding rules to monitor the activities of a victim and collect sensitive information using their personal email.
* Account Manipulation - Additional Email Delegate Permissions (T1098.002): Adversary can also delegate additional permissions to a mailbox to maintain persistent access to a controlled email account.

### IOCs and valuable infos:

* Is the operation on mailbox or on a inboxrule?
* Who did the operation?
* What's the forwarding email if exists
* Are permissions added to a mailbox?
* Is the inbox rule suspicious?

### Queries used:

* The following query displays the details about the rules recently created on inboxes:

```

OfficeActivity
| where Operation in~ ("New-InboxRule", "Set-InboxRule")  
| extend params = parse_json(Parameters) 
| mv-expand params  
| extend value_Name = tostring(bag_keys(params)[0]), value_Value = tostring(bag_keys(params)[1]) 
| extend Name = tostring(params[value_Name]), Value = tostring(params[value_Value])
| project TimeGenerated,UserId, Parameter = pack(Name, Value)


//I'm currently working on how to dynamically spread parameters on the same row 
instead of on different rows
```



### Actions taken to mitigate the threat:







### Threat hunting queries:

* Query to detect all external email forwarding from inbox setup or inbox rules (you can customize and add your trusted domains ):

```
OfficeActivity
| where Operation in~ ("Set-Mailbox", "New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend ForwardingAddress = extract(@"Forward.*?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", 1, tostring(Parameters))
| where isnotempty(ForwardingAddress) and not(ForwardingAddress has_any ("@trusted_domain1","@trusted_domain2"))
| project TimeGenerated, RecordType, Operation, UserType, UserId, ForwardingAddress, Parameters
```

* Query that leverage New-InboxRule to detect deleted phishing emails from inboxes to remove tracks of the attack after a successful compromise:

```
Need to determine first the keywords from email that we receive that indicates
a user compromise
```

&#x20;([https://analyticsrules.exchange/analyticrules/7b907bf7-77d4-41d0-a208-5643ff75bf9a/](https://analyticsrules.exchange/analyticrules/7b907bf7-77d4-41d0-a208-5643ff75bf9a/))





### Extensive list of parameters for each operation:

New-InboxRule

{% embed url="https://learn.microsoft.com/en-us/powershell/module/exchange/new-inboxrule?view=exchange-ps" %}

```
New-InboxRule
   [-Name] <String>
   [-AlwaysDeleteOutlookRulesBlob]
   [-ApplyCategory <MultiValuedProperty>]
   [-ApplySystemCategory <MultiValuedProperty>]
   [-BodyContainsWords <MultiValuedProperty>]
   [-Confirm]
   [-CopyToFolder <MailboxFolderIdParameter>]
   [-DeleteMessage <Boolean>]
   [-DeleteSystemCategory <MultiValuedProperty>]
   [-DomainController <Fqdn>]
   [-ExceptIfBodyContainsWords <MultiValuedProperty>]
   [-ExceptIfFlaggedForAction <String>]
   [-ExceptIfFrom <RecipientIdParameter[]>]
   [-ExceptIfFromAddressContainsWords <MultiValuedProperty>]
   [-ExceptIfHasAttachment <Boolean>]
   [-ExceptIfHasClassification <MessageClassificationIdParameter[]>]
   [-ExceptIfHeaderContainsWords <MultiValuedProperty>]
   [-ExceptIfMessageTypeMatches <InboxRuleMessageType>]
   [-ExceptIfMyNameInCcBox <Boolean>]
   [-ExceptIfMyNameInToBox <Boolean>]
   [-ExceptIfMyNameInToOrCcBox <Boolean>]
   [-ExceptIfMyNameNotInToBox <Boolean>]
   [-ExceptIfReceivedAfterDate <ExDateTime>]
   [-ExceptIfReceivedBeforeDate <ExDateTime>]
   [-ExceptIfRecipientAddressContainsWords <MultiValuedProperty>]
   [-ExceptIfSentOnlyToMe <Boolean>]
   [-ExceptIfSentTo <RecipientIdParameter[]>]
   [-ExceptIfSubjectContainsWords <MultiValuedProperty>]
   [-ExceptIfSubjectOrBodyContainsWords <MultiValuedProperty>]
   [-ExceptIfWithImportance <Importance>]
   [-ExceptIfWithinSizeRangeMaximum <ByteQuantifiedSize>]
   [-ExceptIfWithinSizeRangeMinimum <ByteQuantifiedSize>]
   [-ExceptIfWithSensitivity <Sensitivity>]
   [-FlaggedForAction <String>]
   [-Force]
   [-ForwardAsAttachmentTo <RecipientIdParameter[]>]
   [-ForwardTo <RecipientIdParameter[]>]
   [-From <RecipientIdParameter[]>]
   [-FromAddressContainsWords <MultiValuedProperty>]
   [-HasAttachment <Boolean>]
   [-HasClassification <MessageClassificationIdParameter[]>]
   [-HeaderContainsWords <MultiValuedProperty>]
   [-Mailbox <MailboxIdParameter>]
   [-MarkAsRead <Boolean>]
   [-MarkImportance <Importance>]
   [-MessageTypeMatches <InboxRuleMessageType>]
   [-MoveToFolder <MailboxFolderIdParameter>]
   [-MyNameInCcBox <Boolean>]
   [-MyNameInToBox <Boolean>]
   [-MyNameInToOrCcBox <Boolean>]
   [-MyNameNotInToBox <Boolean>]
   [-PinMessage <Boolean>]
   [-Priority <Int32>]
   [-ReceivedAfterDate <ExDateTime>]
   [-ReceivedBeforeDate <ExDateTime>]
   [-RecipientAddressContainsWords <MultiValuedProperty>]
   [-RedirectTo <RecipientIdParameter[]>]
   [-SendTextMessageNotificationTo <MultiValuedProperty>]
   [-SentOnlyToMe <Boolean>]
   [-SentTo <RecipientIdParameter[]>]
   [-SoftDeleteMessage <Boolean>]
   [-StopProcessingRules <Boolean>]
   [-SubjectContainsWords <MultiValuedProperty>]
   [-SubjectOrBodyContainsWords <MultiValuedProperty>]
   [-WhatIf]
   [-WithImportance <Importance>]
   [-WithinSizeRangeMaximum <ByteQuantifiedSize>]
   [-WithinSizeRangeMinimum <ByteQuantifiedSize>]
   [-WithSensitivity <Sensitivity>]
   [<CommonParameters>]
```

