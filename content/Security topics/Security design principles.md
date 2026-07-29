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