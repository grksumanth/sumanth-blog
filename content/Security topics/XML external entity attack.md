---
title: XML external entity attack nuance
draft: false
tags:
  - XXE
description: Nuances when testing for XXE in services
---
 
I was reading a hack the box article and realized that even though the service only uses JSON to parse the input. There is a good chance that if you change the header to accept xml/text and pass in the XML. There is a good online [JSON to XML](https://convertjson.com/json-to-xml.htm) convertor that converts the JSON to XML and it can be passed to the service.

JSON is very strict in terms of what can be defined and does not have additional parsing capabilities. This allows the services that are parsing the data to be stringent and apply input sanitization and filtering easy. This is not the case with XML there is often encoding involved and the parsers decode before passing it to the services. This creates a vulnerability allowing malformed inputs to get to the backend. 