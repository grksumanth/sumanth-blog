---
title: Design principles
draft: false
tags:
  - design
  - security
description: design principles learnt over years
---

I wanna document design principles that I've learnt over the years some of them gave me permanent scars.

1. Any UUID based string should have an unique prefix attached to it. It seems redundant but when you are searching through logs for things that should never be disclosed like a UUID. This one pattern will save your ass during log deep dives and analysis.
2. Sending authentication token in URL should be shunned upon too many places where there is a scope for it to be logged. I logged into a public computer I do not want my authorization tokens to be shown in the browser history for others to strip it and use the authentication token. If the token is unscoped you are screwed!
3. Trusting an multi-turn agent is always a pain and remember it will be broken if it hasn't been already. The only way is to ensure that the sandboxing is done properly so that there are no cross account requests or data exfiltration mechanisms. Images are also an attack vector in multi expert echo system.
4. Create a boatload of functional tests and negative authorization tests. I think this will be the future where functional and security tests run aggressively to ensure that there are no bugs in production or in pre-production. 
5.  Do not reuse the keys thats used for the encryption. I personally find this dependent on the threat model e.g: The notification encryption mechanism that we built has 1 key per device per session. If a customer logs out of the app or factory reset the key is lost and cannot be recovered. In this case I prefer reusing the key for multiple use cases. FYI NIST strongly suggests otherwise. 
6. RSA is really powerful trap door function it can be reused both ways public key can encrypt and private key can decrypt and vice versa. Does that mean you can encrypt with private key and decrypt with public? The answer depends on is your public key actually public or is it a notion? 
7. Identity propagation is really important and data custodians are the only services that should unwrap the identity and validate it. 
8. API keys are obsolete for production workloads use IAM Roles or other credentials. Read more here: https://spiffe.io 
