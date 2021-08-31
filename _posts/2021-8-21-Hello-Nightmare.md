---
layout: post
title: PrintNightmare
published: true
---

#####  Discovery/Initial PoC
######  Release Date of CVEs: June 8 – July 1
 
1. CVE-2021-1675 - Original Spooler RCE vulnerability that was patched by Microsoft. NOT PRINTNIGHTMARE.
    - Patched in Microsoft’s June Patch Tuesday release
2. CVE-2021-34527 – Officially dubbed PrintNightmare, PoC was published that was thought to exploit CVE-2021-1675 unknowingly finding a new exploit for the Spooler, and given this CVE.
    - Patched in OOB Security update
 
#####  Recently Patched
######  Release Date of CVEs: July 15 - August 10
 
1. [CVE-2021-34481](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34481) - Windows Print Spooler Remote Code Execution Vulnerability 
    - Patched in Microsoft’s August Patch Tuesday release
2. [CVE-2021-34483](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34483) - Windows Print Spooler Remote Code Execution Vulnerability 
    - Patched in Microsoft's August Patch Tuesday release
3. [CVE-2021-36936](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36936) – Windows Print Spooler Remote Code Execution Vulnerability 
    - Patched in Microsoft’s August Patch Tuesday release
4. [CVE-2021-36947](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36947) - Windows Print Spooler Remote Code Execution Vulnerability 
    - Patched in Microsoft’s August Patch Tuesday release
 
#####  Unpatched
######  Release Date of CVE: August 11
 
1. CVE-2021-36958 – Print Spooler Remote Code Execution Vulnerability 
    - Unpatched, recommendation to disable Spooler Service.
    - Rumored to be exploited actively in wild
        - Potential PoC video on twitter
 
 
Overall there are 7 Spooler RCE vulnerabilities and fixes for 6 of them. With disregard to the initial Spooler RCE, the CVEs are collectively known as PrintNightmare. The current unpatched vulnerability maintains the workaround to disable the Print Spooler service. The fixes for the 6 patched vulnerabilities are done so across 2 releases:

1. July OOB security update (See KB5005010)
2. August Patch Tuesday Release
