
This note documents the learnings I had over the years I will try my best to document them over here. 

1. Do not reuse the keys thats used for the encryption. I personally find this dependent on the threat model e.g: The notification encryption mechanism that we built has 1 key per device per session. If a customer logs out of the app or factory reset the key is lost and cannot be recovered. In this case I prefer reusing the key for multiple use cases. FYI NIST strongly suggests otherwise. 
2. RSA is really powerful trap door function it can be reused both ways public key can encrypt and private key can decrypt and vice versa. Does that mean you can encrypt with private key and decrypt with public? The answer depends on is your public key actually public or is it a notion? 
3. Identity propagation is really important and data custodians are the only services that should unwrap the identity and validate it. 
