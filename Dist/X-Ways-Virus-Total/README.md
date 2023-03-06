# X-Ways-Virus-Total

# Documentation
This X-Tension uses VirusTotal API to retrieve the score of a given file based on its SHA-1 hash.
No files are sent or extracted.
Multiple files can be selected.
A report table (VirusTotal) is created according to a minimum score.
When using a public key a delay of 15 seconds between queries is applied (4 queries / minutes)


#Configuration
All mandatory settings are in the config.ini file

* apikey : VirusTotal API key
* public : wether it is a public or paid key
* minscore : if the score reaches that threshold the file will be included in the report table



### Libraries Used:
*	curl - curl-vc141-dynamic-x86_64.7.59.0
*	jsoncpp - jsoncpp-vc140-static-32_64.1.8.0
*	openssl - openssl-vc141-static-x86_64.1.0.2

Coded with C++, VisualStudio 2022 Community.

























