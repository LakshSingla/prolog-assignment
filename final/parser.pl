:- dynamic fwrule/2.

add_fwrule(Fate, Rule) :- assertz(fwrule(Fate,Rule)).

fate(Fate, PacketStr) :- fwrule(Fate, RuleStr), split_string(RuleStr, " ", "", Rule), split_string(PacketStr, " ", "", Packet), fwrule_matches(Rule, Packet), !.

fwrule_matches(Rule, Packet) :- rule_parser(Rule, [], Packet).

rule_parser(X, Y, Packet) :- clause_parser(X, Y, Packet).
rule_parser(X, Y, Packet) :- clause_parser(X, Z, Packet), rule_parser(Z, Y, Packet).

clause_parser(X, Y, Packet) :- 
		adpt_clause_matches(X, Y, Packet);
		eth_clause_matches(X, Y, Packet);
		ip_clause_matches(X, Y, Packet).

adpt_clause_matches(["adapter", AdptExpr|W], W, Packet) :- get_keyval(Packet, "adapter", PacketAdptExpr), adpt_expr_matches(AdptExpr,PacketAdptExpr).

eth_clause_matches(["ether", "vid", VidExpr, "proto", ProtoExpr|W], W, Packet) :- get_keyval(Packet, "vid", PacketVidExpr).
eth_clause_matches(["ether", "vid", VidExpr|W], W, Packet) :- true.
eth_clause_matches(["ether", "proto", ProtoExpr|W], W, Packet) :- true.

ip_clause_matches(["ip", "src", "addr", SrcAddrExpr, "dst", "addr", DstAddrExpr|W0], W, Packet) :- condition_matches(W0, W, Packet).
ip_clause_matches(["ip", "addr", AddrExpr|W0], W, Packet) :- condition_matches(W0, W, Packet).
ip_clause_matches(["ip", "src", "addr", SrcAddrExpr|W0], W, Packet) :- condition_matches(W0, W, Packet).
ip_clause_matches(["ip", "dst", "addr", DstAddrExpr|W0], W, Packet) :- condition_matches(W0, W, Packet).
ip_clause_matches(["ip"|W0], W, Packet) :- condition_matches(W0, W, Packet).

condition_matches(["tcp", "dst", "port", DstPortExpr, "src", "port", SrcPortExpr|W], W, Packet) :- true.
condition_matches(["tcp", "dst", "port", DstPortExpr|W], W, Packet) :- true.
condition_matches(["tcp", "src", "port", SrcPortExpr|W], W, Packet) :- true.

condition_matches(["udp", "dst", "port", DstPortExpr, "src", "port", SrcPortExpr|W], W, Packet) :- true.
condition_matches(["udp", "dst", "port", DstPortExpr|W], W, Packet) :- true.
condition_matches(["udp", "src", "port", SrcPortExpr|W], W, Packet) :- true.

condition_matches(["icmp", "type", TypeExpr, "code", CodeExpr|W], W, Packet) :- true.
condition_matches(["icmp", "type", TypeExpr|W], W, Packet) :- true.
condition_matches(["icmp", "code", CodeExpr|W], W, Packet) :- true.

get_keyval([Key, Val| _], Key, Val).
get_keyval([_, _| T], Key, Val) :- get_keyval(T, Key, Val).

adpt_expr_matches(X, X).