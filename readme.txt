#2014400019 Lee In Sup

This program is for arp spoofing

We will be given input ip for spoofing victim.
next, we will send packet for arp_requst to know victim's MAC address(mapping to victim ip).

and finally, we will make arp_reply packet to make victim believe that 
attacker's MAC is gateway's MAC address.

ethernet information is all right, but arp part will be manipulated.


I studied for principle of arp and arp header, and logic for arp spoofing.
I added a file for studying arpspoofing made by on my own.

Now I am at home, and I will test this program tomorrow at school
because on wednesday I have no class and I don't have another pc for testing
in my home.

I compiled with gcc by

gcc -o sendarp getInfo.c sendarp.c -lpcap