
## Objective: 
Investigate suspicious network patterns to identify potential Man-in-the-Middle (MITM) activity.

In this project, I analyzed a packet capture (PCAP) containing a suspected ARP spoofing attack. The goal was to manually identify the attacker, the victim, and the scope of the compromise without relying on automated IDS alerts.

# 1. Technical Concept: The Vulnerability
The Address Resolution Protocol (ARP) connects IP addresses to physical MAC addresses. However, it is stateless and lacks authentication. This allows an attacker to broadcast false "updates" (Gratuitous ARP) to the network, tricking devices into updating their ARP tables with the attacker's MAC address.

# 2. Investigation Phase 1: Identifying the Anomaly
My investigation began by observing the local network traffic. I filtered for ARP packets to establish a baseline of normal behavior (Requests & Replies).

## Observation:
I noticed an abnormal volume of ARP traffic. Specifically, I saw duplicate responses for the same IP address. In a healthy network, an IP should map to only one MAC address.

Filter used: arp.duplicate-address-detected


https://github.com/user-attachments/assets/37c808cc-384e-47fa-95c6-715ba013c85c

Wireshark flagging a duplicate IP address conflict.

# 3. Investigation Phase 2: Isolating the Attacker
To understand the conflict, I drilled down into the specific IP triggering the warnings: 192.168.1.1 (The Default Gateway).

## The Conflict:

Legitimate Gateway: MAC 50:78:b3:f3:cd:f4 correctly owns 192.168.1.1.

Suspicious Host: A device with MAC 00:0c:29:e2:18:b4 also claimed to be 192.168.1.1.

By analyzing the timeline, I saw the suspicious host (...b4) sending a flood of ARP packets claiming to be the router. This is a clear indication of IP Spoofing.

Filter used: arp.opcode == 2 and arp.src.proto_ipv4 == 192.168.1.1
(Note: This filter isolates all ARP replies claiming to be the gateway, revealing two different MAC addresses claiming the IP.)


https://github.com/user-attachments/assets/ada06ce9-3dc5-407f-88e8-1f13344b145a

We can see the attacker (MAC ending in b4) flooding the network with falsified ARP records.

# 4. Investigation Phase 3: Confirming Man-In-The-Middle (MITM)
Proving the spoofing isn't enough; I needed to prove the impact. If the attack was successful, traffic meant for the victim should be flowing through the attacker's machine.

I switched my view to HTTP traffic and added the "Src/Dst MAC Address" as columns in the Wireshark pane.

## The Smoking Gun:

The victim (192.168.1.12) was trying to browse the web.

However, the Destination MAC for these HTTP packets was NOT the router.

The Destination MAC was 00:0c:29:e2:18:b4 (The Attacker).

This confirmed that the attacker had successfully poisoned the victim's ARP table and was intercepting cleartext HTTP traffic.

Filter used: http and eth.dst == 00:0c:29:e2:18:b4 (note: we can see that the post request contains username and password)


https://github.com/user-attachments/assets/b0f0b953-68c5-4afb-9c59-f512a5bc71c5



Based on the manual analysis of the PCAP, the following network entities were identified and mapped during the investigation.

| Role     | IP Address   | MAC Address       | Notes                                                         |
| -------- | ------------ | ----------------- | ------------------------------------------------------------- |
| Attacker | 192.168.1.25 | 00:0c:29:e2:18:b4 | Originated the ARP flood and intercepted HTTP traffic (MITM). |
| Gateway  | 192.168.1.1  | 50:78:b3:f3:cd:f4 | Legitimate router being spoofed by the attacker.              |
| Victim   | 192.168.1.12 | 00:0c:29:98:c7:a8 | Traffic was redirected through the attacker.                  |

The following display filters were used to isolate suspicious activity and validate the attack.

| Goal                            | Wireshark Filter                      |
| ------------------------------- | ------------------------------------- |
| Basic ARP Traffic               | `arp`                                 |
| Detect Duplicate IPs            | `arp.duplicate-address-detected`      |
| Isolate ARP Requests (Opcode 1) | `arp.opcode == 1`                     |
| Spot ARP Scanning / Flooding    | `arp.dst.hw_mac == 00:00:00:00:00:00` |
| Track Attacker MAC Address      | `eth.addr == 00:0c:29:e2:18:b4`       |

# Lessons Learned
Baseline Knowledge is Critical: You cannot detect spoofing if you do not know what "normal" looks like. Recognizing that 50:78... was the correct Gateway MAC and 00:0c... was the imposter required knowing the network topology beforehand.

The "Illusion" of Layer 3: I learned that relying solely on IP addresses for analysis is dangerous. In this case, the IP headers looked completely normal; the attack was entirely hidden in the Data Link Layer (Layer 2). Always inspect MAC headers during local network investigations.

Filter Efficiency: An ARP flood creates thousands of packets. Learning to combine filters (e.g., arp.opcode == 2 AND arp.src.proto_ipv4 == [Gateway IP]) was essential to isolate the malicious packets from the background noise.

# Limitations & Challenges
Encrypted Traffic (HTTPS/HSTS): While I successfully captured HTTP traffic in this lab, in a real-world scenario, most traffic is encrypted (HTTPS). A standard ARP spoof might disrupt the connection, but I would not be able to see the data contents without additional SSL stripping tools, which are less effective against modern HSTS-enabled sites.

Passive Analysis Delays: Wireshark is a passive analysis tool. By the time I loaded the PCAP and found the anomaly, the attack had already occurred. In a live environment, this detection needs to be automated (e.g., using IDS rules or Python scripts) to block the attacker in real-time.

Switch-Level Protections: This analysis assumes a basic network switch. If Dynamic ARP Inspection (DAI) were enabled on the network hardware, these malicious packets would have been dropped automatically, rendering the attack unsuccessful.
