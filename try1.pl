checkfate(Packet) :- rule(Rule, Fate), check_compatibility(Rule, Packet), write(Fate).

check_compatibility(Rule, Packet) :- rule_parser(Rule, [], Packet).
rule_parser(Rule1, Rule2, Packet) :- clause_parser(Rule1, Rule2, Packet).
rule_parser(Rule1, Rule2, Packet) :- clause_parser(Rule1, Rule3, Packet), rule_parser(Rule3, Rule2, Packet).
clause_parser(["adapter",expression|Left], Left, Packet) :- check_adapter(expression, Packet).

clause_parser(["ethernet","proto",protocol,"vid",vid|Left]) :- check_ethernet_proto, check_ethernet_vid.
clause_parser(["ethernet","proto",protocol|Left],Left,Packet) :- get_protocol(Packet, Packetprotocol), match_proto(protocol,Packetprotocol)
clause_parser(["ethernet","vid",vid|Left],Left,Packet) :- check_ethernet_vid(vid,Packet)


rule("adapter A tcp src port 80", "allow").
rule("adapter any ip src addr 192.168.1.1", X, "drop".
rule(_,_,"deny").


extract_srcport(["srcport",Port|_],Port).
extract_srcport([_,_|T],Port) :- extract_srcport(T,Port). 

"adapter a srcport 80 destport 90"

src_port(Packet, Srcport) :- Packet

"ad A srcprt 80 destprt 90"