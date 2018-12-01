fwrule("accept", "adapter A").
fwrule("drop", "adapter A ip addr 192.168.1.1").
fwrule("reject", "adapter !B ether vid 20").

fwdefault("drop").