:- dynamic fwrule/2.
:- dynamic fwdefault/1.

:- [ipcompare].
:- [rangecheck].
:- [rule_verification].

add_fwrule(Fate, Rule) :-
	verify_fwrule(Rule), 
	assertz(fwrule(Fate,Rule));
	write("Please enter a valid firewall rule.").
change_fwdefault(DefaultFate) :- retract(fwdefault(_)), assertz(fwdefault(DefaultFate)).
fwdefault("Drop").

fate(Fate, PacketStr) :- 
	fwrule(Fate, RuleStr),
	split_string(RuleStr, " ", "", Rule),
	split_string(PacketStr, " ", "", Packet),
	fwrule_matches(Rule, Packet),
	!.

fate(Fate, _) :- write("Resorting to firewall default"), fwdefault(Fate).

%  Default query
%  fate("drop", _).

fwrule_matches(Rule, Packet) :- rule_parser(Rule, [], Packet).

rule_parser(X, Y, Packet) :- clause_parser(X, Y, Packet).
rule_parser(X, Y, Packet) :- clause_parser(X, Z, Packet), rule_parser(Z, Y, Packet).

clause_parser(X, Y, Packet) :- 
		adpt_clause_matches(X, Y, Packet);
		eth_clause_matches(X, Y, Packet);
		ip_clause_matches(X, Y, Packet).

adpt_clause_matches(["adapter", Adpt|W], W, Packet) :- 
	get_keyval(Packet, "adapter", PktAdpt), 
	adpt_expr_matches(Adpt,PktAdpt).

eth_clause_matches(["ether", "vid", Vid, "proto", NlProto|W], W, Packet) :- 
	get_keyval(Packet, "vid", PktVid),
	num_expr_matches(Vid, PktVid),
	get_keyval(Packet, "nlproto", PktNlProto),
	num_expr_matches(NlProto, PktNlProto).
eth_clause_matches(["ether", "vid", Vid|W], W, Packet) :-
get_keyval(Packet, "vid", PktVid),
	num_expr_matches(Vid, PktVid).
eth_clause_matches(["ether", "proto", NlProto|W], W, Packet) :-
	get_keyval(Packet, "nlproto", PktNlProto),
	num_expr_matches(NlProto, PktNlProto).

ip_clause_matches(["ip", "src", "addr", SrcIp, "dst", "addr", DstIp|W0], W, Packet) :- 
	get_keyval(Packet, "srcip", PktSrcIp),
	ip_expr_matches(SrcIp, PktSrcIp),
	get_keyval(Packet, "dstip", PktDstIp),
	ip_expr_matches(DstIp, PktDstIp),
	condition_matches(W0, W, Packet).

ip_clause_matches(["ip", "addr", Ip|W0], W, Packet) :- 
	get_keyval(Packet, "srcip", PktSrcIp),
	ip_expr_matches(Ip, PktSrcIp),
	condition_matches(W0, W, Packet);
	get_keyval(Packet, "dstip", PktDstIp),
	ip_expr_matches(Ip, PktDstIp),
	condition_matches(W0, W, Packet).

ip_clause_matches(["ip", "src", "addr", SrcIp|W0], W, Packet) :- 
	get_keyval(Packet, "srcip", PktSrcIp),
	ip_expr_matches(SrcIp, PktSrcIp),
	condition_matches(W0, W, Packet).

ip_clause_matches(["ip", "dst", "addr", DstIp|W0], W, Packet) :- 
	get_keyval(Packet, "dstip", PktDstIp),
	ip_expr_matches(DstIp, PktDstIp),
	condition_matches(W0, W, Packet).

ip_clause_matches(["ip"|W0], W, Packet) :- condition_matches(W0, W, Packet).

condition_matches(["tcp", "dst", "port", DstPort, "src", "port", SrcPort|W], W, Packet) :-
	get_keyval(Packet, "tlproto", "tcp"),
	get_keyval(Packet, "srcport", PktSrcPort),
	num_expr_matches(SrcPort, PktSrcPort),
	get_keyval(Packet, "dstport", PktDstPort),
	num_expr_matches(DstPort, PktDstPort).
condition_matches(["tcp", "dst", "port", DstPort|W], W, Packet) :-
	get_keyval(Packet, "tlproto", "tcp"),
	get_keyval(Packet, "dstport", PktDstPort),
	num_expr_matches(DstPort, PktDstPort).
condition_matches(["tcp", "src", "port", SrcPort|W], W, Packet) :-
	get_keyval(Packet, "tlproto", "tcp"),
	get_keyval(Packet, "srcport", PktSrcPort),
	num_expr_matches(SrcPort, PktSrcPort).

condition_matches(["udp", "dst", "port", DstPort, "src", "port", SrcPort|W], W, Packet) :-
	get_keyval(Packet, "tlproto", "udp"),
	get_keyval(Packet, "srcport", PktSrcPort),
	num_expr_matches(SrcPort, PktSrcPort),
	get_keyval(Packet, "dstport", PktDstPort),
	num_expr_matches(DstPort, PktDstPort).
condition_matches(["udp", "dst", "port", DstPort|W], W, Packet) :-
	get_keyval(Packet, "tlproto", "udp"),
	get_keyval(Packet, "dstport", PktDstPort),
	num_expr_matches(DstPort, PktDstPort).
condition_matches(["udp", "src", "port", SrcPort|W], W, Packet) :-
	get_keyval(Packet, "tlproto", "udp"),
	get_keyval(Packet, "srcport", PktSrcPort),
	num_expr_matches(SrcPort, PktSrcPort).

condition_matches(["icmp", "type", IcmpType, "code", IcmpCode|W], W, Packet) :-
	get_keyval(Packet, "tlproto", "icmp"),
	get_keyval(Packet, "icmptype", PktIcmpType),
	num_expr_matches(IcmpType, PktIcmpType),
	get_keyval(Packet, "icmpcode", PktIcmpCode),
	num_expr_matches(IcmpCode, PktIcmpCode).
condition_matches(["icmp", "type", IcmpType|W], W, Packet) :-
	get_keyval(Packet, "tlproto", "icmp"),
	get_keyval(Packet, "icmptype", PktIcmpType),
	num_expr_matches(IcmpType, PktIcmpType).
condition_matches(["icmp", "code", IcmpCode|W], W, Packet) :-
	get_keyval(Packet, "tlproto", "icmp"),
	get_keyval(Packet, "icmpcode", PktIcmpCode),
	num_expr_matches(IcmpCode, PktIcmpCode).

condition_matches(W, W, _).

get_keyval([Key, Val| _], Key, Val).
get_keyval([_, _| T], Key, Val) :- get_keyval(T, Key, Val).

% adpt_expr_matches(X, X).
adpt_expr_matches("any", _).
adpt_expr_matches(Adpt, PktAdpt) :-
	lies_in_not_Expr(Adpt, PktAdpt, false).

num_expr_matches("any", _).
num_expr_matches(NumExpr, Val):-
	lies_in_not_Expr(NumExpr, Val, true).

% Are empty conditions being handled ?
