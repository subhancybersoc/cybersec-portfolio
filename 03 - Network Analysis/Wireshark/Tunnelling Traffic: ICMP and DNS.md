# Objective: 
Identify unauthorized data exfiltration and Command & Control (C2) traffic hidden within standard, trusted protocols.

In this investigation, I focused on "living off the land" network techniques. Attackers often bypass firewalls by encapsulating malicious traffic (SSH, HTTP, or Shell commands) inside ICMP (Ping) and DNS packets, as these are rarely blocked in enterprise environments.

# 1. ICMP Tunneling: Data Hidden in Plain Sight
ICMP is designed for diagnostics, but its "Data" payload section can be abused to carry unauthorized protocols.

## The Investigation:
While monitoring a network segment, I noticed an anomaly in ICMP packet sizes. Standard pings are usually small and consistent. However, I discovered packets where the payload was significantly larger than the standard 64 bytes.

## Detection Strategy:
I filtered for ICMP packets with an unusual data length. Upon inspecting the "Data" field of these packets, I found signatures of an encapsulated protocol [SSH] instead of the standard alphabet pattern used in legitimate pings.

Filter used: data.len > 64 and icmp


https://github.com/user-attachments/assets/0234b2f2-19f9-490f-8b47-6bc6da86d708

As we can see there is an OPEN SSH C2 establishement happening : 
<img width="1300" height="340" alt="SSH" src="https://github.com/user-attachments/assets/25bce939-0cfd-4d74-a4da-62ebcd43417f" />



# 2. DNS Tunneling: The "Encoded Subdomain" Technique
DNS is the "phonebook of the internet." Attackers use it for C2 by encoding commands into subdomain strings. For example: dGhlLXBhc3N3b3JkLWlzLWNvb2tpZQ==.attacker.com.

## The Investigation:
I performed a statistical analysis of DNS queries and found a massive volume of requests to a single external domain. These queries didn't look like normal websites; they were long, randomized strings of characters acting as subdomains.

## Detection Strategy:
I used a filter to exclude local noise (mdns) and focused on queries where the name length exceeded 15 characters, which is a common threshold for DGA (Domain Generation Algorithms) or tunneling tools like dnscat2.

Filter used: dns.qry.name.len > 15 and !mdns

As we can see there is quite some suspicious Domains names here !

https://github.com/user-attachments/assets/3f4c1c21-af69-4227-9d6e-14ef67cd70ac


# Lessons Learned
Protocol Abuse: I learned that "Allowing" a protocol doesn't mean it's safe. A firewall rule that allows "All ICMP" is a wide-open door for a persistent threat actor.

Payload Inspection: Looking at the structure of the packet isn't enough; you must look at the content. Seeing "SSH" headers inside an "ICMP" packet is a 100% confirmation of malicious tunneling.

Beating the "Noise": DNS traffic is incredibly noisy. Learning to use the !mdns filter was vital to remove local "chatter" (like printers and chromecasts) so I could focus on external threats.

# Limitations & Next Steps
Encryption within Tunnels: Advanced attackers will encrypt the data before putting it in the ICMP or DNS packet. In those cases, I wouldn't see "SSH" or "HTTP" strings, only high-entropy random data.

Python for Frequency Analysis: Manually scrolling through DNS queries is slow. My next step is to write a Python script using Scapy or Pandas to calculate the Entropy of DNS strings. High entropy usually indicates encoded/encrypted data.

SIEM Thresholds: I want to practice setting up alerts in a SIEM (like Splunk) that trigger when a single internal host makes more than 500 unique DNS queries to a single TLD (Top Level Domain) within one minute.
