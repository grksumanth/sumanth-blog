---
title: Journey into Sumanth's brain
---
**Disclaimer:** This is my personal blog and my posts/views does not reflect my current or previous Employers. 

This blog is a gateway into my brain and life. I try to keep this blog updated with my learnings and help anyone who might find this information useful. 
## Who am I?
Sumanth is an enthusiastic human who loves to work on cybersecurity, lift weights, hiking and enjoy life in general. If I didn't bring up biryani my intro would not be complete - I live for biryani! [[Professional experience]] in case you are interested.

## Product/Feature launches
Over my career I have performed security for multiple products/features I'm going to the list the ones that are public:
1. [Amazon Photos Gather](https://www.amazon.com/gp/help/customer/display.html?nodeId=TIMz8VqExFCEq5nYlv) - Allows customers to upload anonymously to your Amazon Photos account. I influenced and tested the security of this feature. 
2. [Natural language search](https://www.youtube.com/watch?v=Htyo6yfmI3U) - This is semantic search which allows customers to search using natural language. This is a massive change in multiple services to support this feature. I influenced and tested the security for this feature. 
3. [Image search](https://www.techspot.com/news/107352-amazon-photos-app-can-now-identify-products-images.html) - Allows customers to search for a product on Amazon directly from the app. This gets too much heat for what the feature is; don't believe me look at the network calls. 
4. [Shutterfly X Amazon Photos](https://www.linkedin.com/posts/shutterfly_new-partnership-alert-shutterfly-and-activity-7251620915317284864-fJ3r) - Allows customers to print using Shutterfly; It's a standard OAuth2 implementation with a twist. I made the requirement to expire the consent after 6 months and customers need to consent again after 6 months. Customers often forget to check who has access to their personal data, this is especially disastrous in case of Photos. As a customer I can upload something sensitive without remembering that they have consented to share the data with Shutterfly. This made me campaign for this expectation and its finally live in production. I wish all Oauth2 is like this where expiry can be defined by the customer.
5. [Alexa+ X BMW](https://www.aboutamazon.com/news/devices/alexa-plus-bmw-voice-assistant) - I worked on integrating the services and build signing strategy for the Amazon generated binaries to be used and shared across vendors like BMW. Th signing strategy allows vendors to verify the library signature during runtime mitigating supply chain security risks. 
6. Amazon Photos Notification encryption - Designed encryption system to send critical data over notification without Google nor Apple can read the data while in transit. 
7. Amazon Photos Upload service hardening - I worked on hardening the security posture of Upload service using SELinux, Seccomp, cgroups and namespaces. Leveraged AWS nitro enclave to ensure that the private key never leaves the host. 
8. [Amazon Alexa Photo Frame](https://www.amazon.com/gp/product/B0H3CPKKVN/) - Led the security for this product including security reviews for new services required to work which includes voice notes and audited boot loader stack. We redesigned the sharing for this product and I did the review and collaborated to create the new sharing system.
9. MoEngage X Amazon Photos - Created and validated the [[AWS IAM identity verification| requirements/design]] for MoEngage to support [IAM sigv4 auth](https://www.moengage.com/docs/user-guide/settings/account/api-and-api-keys/api-key-dashboard#aws-sts-auth) which led to no API keys being used to authenticate a user. This not only allows Amazon to use this feature but all the other clients of MoEngage can use this moving the needle with a future of no API keys. I'm personally not against API keys just do not like the life span of the keys.

## Guiding Philosophy
I believe digital security is every individual right and I walk towards it one step at a time!

This blog is pretty new so does not contain any info; I need to migrate stuff from my old blog to here. one more to-do lol.

[[Quicklinks]]

