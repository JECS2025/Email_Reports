# SOC100-2: Email Analysis 2

## 1. Email Body & Payloads

### Message & Intent

- `Suspicious language`
    - `*3 headers trying to create an urgent/high priority message:*`
        1. `*X-Priority: 1 (Highest)*`
        2. `*X-Msmail-Priority: High*`
        3. `*Importance: High*`
    - `*No text written in the email.*`

### Links

`*No links directly seen from the body of the email. However, an html attachment is.*`

### Attachments

- Suspicious filetypes:

`.html`

- Attachment checked in:
    - **VirusTotal Detection Summary**
        - File Type: `.html`
        - **`5/60** vendors flagged as malicious`
        - SHA-256 hash: `410a8c2275863dfbe362fe76a59533cad2e54874481ec14d90e364850e366599`
        - Detected:
            - `JS/Redirector.PDX` (Google)
            - `Trojan.JS.Redirector` (Kaspersky)
            - `Trojan.HTML.Agent.axj` (ZoneAlarm)
            
            <aside>
            
            This HTML file likely contains an embedded JavaScript redirector used for phishing or credential theft.
            
            </aside>
            
       <details>
       <summary>VirusTotal Screenshot</summary>
          
       ![VirusTotal Screenshot](SOC100-2/assets/VirusTotal_Email_Analysis_2.png)

       </details>
            
        
            
    
    📎 *Screenshot provides visual validation of threat detections for reference and reporting.*
    

### Embedded Scripts

- Email Bait:

`var vqTlpKfWbn = "aW5mb0BsZXZlbGVmZmVjdC5jb20=";`  = info@leveleffect.com

*Fake or support address. Could be used to feign legitimacy.*

- Redirect URL

`String.fromCharCode(...)` fully decoded:

```bash
[https://cn.bing.com/ck/a?!&&p=7e9ab7a60ffab264JmltdHM9MTY5MzE4MDgwMCZpZCZpZGVyY2QyNDY4Mi04NDg3LTZmZmUtMWM3LTU1YTk5NDI1YzZl54&u=a1aHR0cHM6Ly9teWltZWdlcy5naXRodWJ1c2VyY29udGVudC5jb20v](https://cn.bing.com/ck/a?!&&p=7e9ab7a60ffab264JmltdHM9MTY5MzE4MDgwMCZpZCZpZGVyY2QyNDY4Mi04NDg3LTZmZmUtMWM3LTU1YTk5NDI1YzZl54&u=a1aHR0cHM6Ly9teWltZWdlcy5naXRodWJ1c2VyY29udGVudC5jb20v)...
```

*Disguised phishing redirect via Bing’s click-tracking path, abused via open redirect features. Not the u= parameter contains a second base64 value, resolves to the actual redirect.*

- Image Source (Base64 encoded image path)

```bash
aHR0cHM6Ly91c2VyLWltYWdlcy5naXRodWJ1c2VyY29udGVudC5jb20vNDkzNzA4MzcvMjQ0MDU3NjgxLWQ5MTM3MDMyLTVjOWYtNDQ2YS05NzgwLTAyZWVmNGY2ZjcwMy5wbmc=
```

[https://user-images.githubusercontent.com/49370837/244057681-d9137032-5c9f-446a-9780-02eef9f6f703.png](https://user-images.githubusercontent.com/49370837/244057681-d9137032-5c9f-446a-9780-02eef9f6f703.png)
*Likely used as a fake logo or screenshot to sell page legitimacy.*

- URL redirection:

`setTimeout(function() { ytePwyksnG.click(); }, 3000);` - waits 3 seconds before simulating a user click on a hidden <a> tag.

Summary — What It Does:

1. Loads a hidden image (for branding)
2. Contains **auto-redirect JavaScript** that builds and clicks a hidden phishing link
3. Points to a Bing redirector → eventually sends the user to a **crafted phishing page**
4. Includes `info@leveleffect.com` to look more legit

---

## 2. Header Analysis

### Spoofing & Delivery

- From: `"Donation [Notification-leveleffect.com](http://notification-leveleffect.com/)[matusima.nobuyuki@khaki.plala.or.jp](mailto:matusima.nobuyuki@khaki.plala.or.jp)" [info@leveleffect.com](mailto:info@leveleffect.com)`
- SPF / DKIM / DMARC:
    - `SPF: Fail - 60.36.166.22` is not authorized to send mail for `leveleffect.com`
    - `DMARC: Fail - neither SPF or DKIM passed`
    - `DKIM: Not present. No cryptographic signature to verify the sender’s identity or message integrity. **So what?`**
        - `Further indicator of a spoofed domain`
        - `Came from a compromised server`
- Return-Path: `info@[leveleffect.com](http://leveleffect.com)` - spoofed. SPF failed so there’s no authority to send mail from the leveleffect.com domain.
- Received**:** `Received: from [127.0.0.1] (really [54.178.91.166]) by [msc12.plala.or.jp](http://msc12.plala.or.jp/)
with ESMTP`
    - `Indicates it comes from 127.0.0.1, aka [localhost](http://localhost) (almost impossible for an external email to come from this)`
    - **`54.178.91.166** belongs to Amazon AWS (Tokyo Region)`
    - `msc12.plala.or.jp flagged this by confirming the forged sender origin`

### Sender Infrastructure

- Apparently sender: ‘info@leveleffect.com’
- Claimed sending IP (via `Received:` header): `54.178.91.166` (Amazon AWS)
- Connecting IP for SPF check: `60.36.166.22`

*Neither IP is authorized to send on behalf of ‘leveleffect.com’*

### Authentication Claims

- `X-Ms-Exchange-Organization-Messagedirectionality: Originating`
- `AuthAs: Internal`
- `AuthMechanism: 02 (NTLM/Kerberos)`
- `X-Ms-Exchange-Organization-Authsource: [MWHPR22MB0014.namprd22.prod.outlook.com](http://mwhpr22mb0014.namprd22.prod.outlook.com/)`

*North American production server. This indicates that it was claimed to be sent from North America, but the SMTP  handshake and mail delivery came from the AWS IP in Japan.*

---

## 3. Context & Infrastructure Pivoting

**SCOPE**

- Message was sent to a single email.
- No known delivery to other internal users
- Recommend:
    - Search mail logs for:
        - “Payment Submitted for Leveleffect Donation”
        - Sender:  `Donation [Notification-leveleffect.com](http://notification-leveleffect.com/)[matusima.nobuyuki@khaki.plala.or.jp](mailto:matusima.nobuyuki@khaki.plala.or.jp)`

### Threat Intelligence

- Potential mail relay abusing to muddle the track; moving from Japan but masked as coming from North America.
- **MITRE mapping**:
    - TA0006 (Credential Access)
    - TA0007 (Discovery)
    - T1566 (Phishing)

---

## 4. Intent & Scope

### Threat Capability

- Credible phishing attempt with base64 encoding to mask the script.

### User Behavior

- User did not report any further action other than reporting the email for suspicious activity.

### Lateral Impact

- No further indications of compromise with any other users. This was sent to 1 recipient and seems like an isolated attempt. However, checks must take place to erase any further worries.

---

## 5. Conclusion & Actions

### Verdict

- Confirmed as a malicious & credible attempt with the mail relay abuse, generation of mail headers to display critical and urgent requirement.

### Actions

- `Block sender/domain/IP`
- `Submit to threat intel`
- `Update detections`
- `update DMARC policy from p=none to p=quarantine or p=reject to enforce handling of failed authentication attempts.`

---

## Final Report Summary

**Subject**: `Re: Payment Submitted for Leveleffect Donation`

**Targeted User**: `info@leveleffect.com`

**Summary**: `Phishing`

**Indicators**:

- Attachment hash: `410a8c2275863dfbe362fe76a59533cad2e54874481ec14d90e364850e366599`
- IP:
    - `127.0.0.1` - Spoof IP (a [localhost](http://localhost) ip)
    - `54.178.97.166` - Real IP (Located in Japan)
    - `60.36.166.22`  - Last hop before SPF check (NTT Communications Corporation / Japan)
    
    **MITRE Techniques**:
    
    - `TA0006 (Credential Access)`
    - `TA0007 (Discovery)`
    - `T1566 (Phishing)`
    
    **Action Taken**: `Blocked`, `Expanded email search for any IOCs` , `further training drawn up to push out to staff of leveleffect.com`, `email security protocol policies to be hardened`
    
    **Confidence**: `High`
    

**General Summary:**

- Suspicious email sent to the [info@leveleffect.com](mailto:info@leveleffect.com) mailbox.
- Edited mail headers viewable to create a sense of urgency and attention requirement.
- “From” email was visibly spoofed.
- Further mail exchange headers were manipulated by stating they were:
    - authenticated by Kerberos (meaning it’d have to come from an account inside the org)
    - internal authenticated, i.e sent by an account inside the organization
    - claimed to be sent from an North American Production Server
- Contradictory to the above, the real IPs were being shown to be coming from Japan; that’s where the SMTP and mail delivery happened from.
- The email attachment displayed base64 coding. Broken apart they displayed multiple attempts of creating an legitimate branding on the site.

---

Definitely a credible attempt at a phishing attack.
