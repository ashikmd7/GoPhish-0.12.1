# Uncontrolled Resource Consumption in ApplyTemplate() in GoPhish v0.12.1 Allows Attackers to Crash the Server (Denial of Service) via an Crafted Malicious Office Document

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Unbounded%20Memory%20Allocation%20in%20Office%20Attachment%20Processing%20Leads%20to%20Server%20DoS/%5B7%5D%20After%20Upload%202.png)

## Summary

A Denial of Service (DoS) vulnerability exists in GoPhish v0.12.1 due to improper handling of Office document attachments during email template processing. When a user uploads a crafted Office document (`.docx`, `.pptx`, `.xlsx`) containing highly compressed data (zip bomb), the backend reads the entire uncompressed content into memory without enforcing any size restrictions. Since Office documents are ZIP archives internally, an authenticated attacker can upload a malicious file that expands to several gigabytes in memory, causing excessive memory consumption and ultimately crashing the GoPhish process. Exploitation requires only a valid authenticated account and results in complete service unavailability.

## Product Information

**Vendor:** [GoPhish](https://getgophish.com/)    
**Product:** [GoPhish](https://github.com/gophish/gophish)  
**Affected Versions:** [v0.12.1](https://github.com/gophish/gophish/releases/tag/v0.12.1)    
**CVSS v3.1:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` (High)  

## Technical Details

The vulnerability exists in the attachment processing logic implemented within `models/attachment.go`. When validating uploaded Office documents, GoPhish treats the file as a ZIP archive and iterates through each embedded file.

During processing, the application reads every file contained inside the archive entirely into memory using `ioutil.ReadAll()`.

```go
// File: models/attachment.go

for _, zipFile := range zipReader.File {
    ff, err := zipFile.Open()
    if err != nil {
        return nil, err
    }

    // Entire uncompressed file is loaded into memory
    // without any size restriction.
    contents, err := ioutil.ReadAll(ff)
    if err != nil {
        return nil, err
    }

    // Further processing...
}
```

The application performs no validation on the uncompressed size of the archive entries before allocating memory.

As a result, an attacker can upload a malicious Office document containing files that decompress into extremely large sizes (for example, several gigabytes). Although the uploaded file itself remains very small, the server attempts to allocate memory for the entire decompressed content, eventually exhausting available system memory. Once memory exhaustion occurs, the operating system terminates the GoPhish process, resulting in a complete Denial of Service condition.

## Vulnerable Component

**Endpoint:** Email Template Attachment Upload Functionality  
**File:** `models/attachment.go`  
**Function:** `ApplyTemplate()`  
**Parameter:** Uploaded attachment file (`.docx`, `.pptx`, `.xlsx`)  

Affected functionality:

* Email Templates > Create/Edit Template > Attachment Upload
* Processing and validation of Office document attachments

## Reproduction Steps

1. Create a zip bomb by generating a large file (for example, 5GB) and compressing it into a ZIP archive.
2. Rename the archive from `bomb.zip` to `exploit.docx`.

The following screenshot demonstrates creation of the malicious file.

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Unbounded%20Memory%20Allocation%20in%20Office%20Attachment%20Processing%20Leads%20to%20Server%20DoS/%5B1%5D%20Exploit%20Process%20\(Python\).png)

3. Log in to the GoPhish administrative interface.
4. Navigate to **Email Templates**.

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Unbounded%20Memory%20Allocation%20in%20Office%20Attachment%20Processing%20Leads%20to%20Server%20DoS/%5B2%5D%20Email%20Templates%20Page.png)

5. Create a new template.

6. Click **Add Files** and select the crafted `exploit.docx` file.

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Unbounded%20Memory%20Allocation%20in%20Office%20Attachment%20Processing%20Leads%20to%20Server%20DoS/%5B3%5D%20New%20Template%20-%20Add%20Files.png)

7. Before uploading the file, monitor the GoPhish process memory usage using `htop`.

The screenshot below shows normal memory consumption before exploitation.

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Unbounded%20Memory%20Allocation%20in%20Office%20Attachment%20Processing%20Leads%20to%20Server%20DoS/%5B4%5D%20Before%20Upload.png)

8. Upload the malicious Office document.

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Unbounded%20Memory%20Allocation%20in%20Office%20Attachment%20Processing%20Leads%20to%20Server%20DoS/%5B5%5D%20Upload%20the%20Exploit.png)

9. Save the email template.

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Unbounded%20Memory%20Allocation%20in%20Office%20Attachment%20Processing%20Leads%20to%20Server%20DoS/%5B6%5D%20Save%20Template.png)

10. Observe that memory consumption immediately spikes to several gigabytes.

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Unbounded%20Memory%20Allocation%20in%20Office%20Attachment%20Processing%20Leads%20to%20Server%20DoS/%5B7%5D%20After%20Upload.png)

11. Eventually, the operating system kills the GoPhish process due to memory exhaustion.

![](https://github.com/ashikmd7/GoPhish-0.12.1/blob/main/Unbounded%20Memory%20Allocation%20in%20Office%20Attachment%20Processing%20Leads%20to%20Server%20DoS/%5B8%5D%20Process%20Killed%20by%20zsh%20Due%20to%20MEM%20Overload.png)

## Proof of Concept

The following Python logic was used to generate a highly compressed file that expands to approximately 5GB when decompressed:

```python
import zipfile

payload_size = 5 * 1024 * 1024 * 1024  # 5GB

with zipfile.ZipFile("bomb.zip", "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("huge.bin", b"\x00" * payload_size)

print("Created bomb.zip")
```

Rename the generated archive:

```bash
mv bomb.zip exploit.docx
```

When the file is uploaded and the template is saved, GoPhish invokes `ApplyTemplate()`, which processes the archive and attempts to fully load `huge.bin` into memory using `ioutil.ReadAll()`, causing excessive memory allocation and process termination.

## Impact

Any authenticated GoPhish user can repeatedly crash the entire application by uploading a single malicious Office document. Since the vulnerable code executes during attachment validation, exploitation requires minimal effort and no user interaction beyond uploading the file. Successful exploitation results in complete service unavailability, interruption of phishing campaigns, administrative lockout, and requires manual intervention to restart the application. Attackers can continuously repeat the attack to keep the service offline indefinitely.

## Remediation

GoPhish should never read unbounded data from user-controlled archives. Before processing any ZIP entry, the application should validate both compressed and uncompressed sizes and reject files exceeding a predefined limit. Replace direct usage of `ioutil.ReadAll()` with an `io.LimitedReader` or equivalent mechanism to enforce strict size limits (for example, 50MB per entry). Additionally, implement safeguards against zip bombs by tracking cumulative extracted size and limiting the total number of files processed within an archive.

```go
const maxFileSize = 50 * 1024 * 1024 // 50MB

lr := &io.LimitedReader{
    R: ff,
    N: maxFileSize,
}

contents, err := ioutil.ReadAll(lr)

if lr.N == 0 {
    return nil, errors.New("attachment exceeds maximum allowed size")
}
```

```
This vulnerability was discovered by Ashik Mohamed (ashikmd7)
on 21/06/2026
```
