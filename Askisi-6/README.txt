Team 39
Konstantinos Kontos 2022030116
Christos Kadas 2022030076

When we run the firewall, new rejected IPs are imported to the IPtables in 
the kernel. We can also print and load rules from the "rules" files.
Type -help for more info.

Question:
After configuring the firewall rules, test your script by visiting your 
favorite websites without any other adblocking mechanism (e.g., adblock 
browserextensions). Can you see ads? Do they load? Some ads persist, why?

Answer:
We can still see some ads because they are from domains which are not currently
blocked in the config so firewall has no effect on them.