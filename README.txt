# VNF_Tool
This is just a simple tool I wrote to do some testing for some NFV/VNF work I'm doing.
I like the ability to read from a PCAP file and send data.  Gives me a repeatable set of data to test with.

It basically takes data from a source (either an ethernet device, or a PCAP file) does any optional
manipulation (SRC/DEST MAC, VLAN TAG, RAW data) and blasts it out to another device if specified.

I like to use it in my VM to receive data, and flip it right back out the same port after maybe some manipulation.

Isn't super fast.  I haven't coded C in like 10 years, so it's not very elegant code.

Requires libpcap!

thanx,

Patrick Kutch
