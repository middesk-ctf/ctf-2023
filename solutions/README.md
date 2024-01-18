# Middesk CTF 2023

Theme: Developing a secure file storage and sharing application.

## Day 1: Admin Login Vulnerability

- *Feature*: The app is only a simple login page for admin users. Once logged in, an admin can access any file on the file system, including the secret. No other features have been implemented yet.
- *Vulnerability*: A flaw in the password verification process that can be exploited to gain unauthorized access.

## Day 2: Privilege Escalation via Profile Editing

- *Feature*: New users can now sign up to use the app. We haven't yet implemented personal file storage, but users can customize their profile, including changing their display name with Emoji support!
- *Vulnerability*: A SQL injection vulnerability in the profile editing feature allows users to modify the role column in the database when they update their display name, potentially escalating their privileges.

## Day 3: Insecure API Endpoint for File Metadata

- *Feature*: A RESTful API for accessing files and metadata like creation date, owner, and size.
- *Vulnerability*: The API endpoint for fetching file metadata does not properly authenticate requests, allowing unauthorized access to files, including that of the secret file. Though the file IDs are uknown, the user can iterate through sequential File IDs until they find the corresponding secret file.

## Day 4: Cross-Site Scripting (XSS) in File Sharing
- *Feature*: A feature that allows a user to share a file with another user, along with a message about the file.
- *Vulnerability*: The form field for specifying a message to share is vulnerable to a cross-site scripting (XSS) attack. A message containing a malicious script can be shared with an admin, which, when viewed, executes and may lead to unauthorized actions or data exposure such as unintentionally sharing their secret file with the attacker.

## Day 5: Insecure Custom Crypto Implementation
- *Feature*: Advanced authentication using a custom crypto-based method. Users are assigned public/private key pairs for signing tokens to authenticate API requests. The 
- *Vulnerability*: The custom implementation of the Digital Signature Algorithm (DSA) uses a constant, predictable value of k (humorously set to 4 as a reference to the XKCD comic). This flaw allows the calculation of the admin's private key. Exploitation Goal: Participants crack the admin's private key by exploiting the weak implementation of DSA. This will require some basic understanding of how DSA works. Once the admin's private key has been extracted, the player can use it to forge a token to access the secret file.

Each day presents a unique and progressively complex security challenge, covering a range of vulnerabilities from basic authentication flaws to intricate and specific cryptographic weaknesses. This setup provides a comprehensive and engaging learning experience in cybersecurity.

