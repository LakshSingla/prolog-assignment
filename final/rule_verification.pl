% Header imports

verify_fwrule(Fate, PacketStr) :- 
	split_string(RuleStr, " ", "", Rule),
	rule_parser(Rule, []).

rule_parser(X, Y) :- clause_parser(X, Y).
rule_parser(X, Y) :- clause_parser(X, Z), rule_parser(Z, Y).

clause_parser(X, Y) :- 
		adpt_clause_matches(X, Y);
		eth_clause_matches(X, Y);
		ip_clause_matches(X, Y).

adpt_clause_matches(["adapter", Adpt|W], W) :- 
	adpt_expr_valid(Adpt).

eth_clause_matches(["ether", "vid", Vid, "proto", NlProto|W], W) :- 
	vid_expr_valid(Vid),
	proto_expr_valid(NlProto).
eth_clause_matches(["ether", "vid", Vid|W], W) :-
	vid_expr_valid(Vid).
eth_clause_matches(["ether", "proto", NlProto|W], W) :-
	proto_expr_valid(NlProto).

ip_clause_matches(["ip", "src", "addr", SrcIp, "dst", "addr", DstIp|W0], W) :- 
	ip_expr_valid(SrcIp),
	ip_expr_valid(DstIp),
	condition_matches(W0, W).

ip_clause_matches(["ip", "addr", Ip|W0], W) :- 
	ip_expr_valid(Ip, PktSrcIp),
	condition_matches(W0, W).

ip_clause_matches(["ip", "src", "addr", SrcIp|W0], W) :- 
	ip_expr_valid(SrcIp),
	condition_matches(W0, W).

ip_clause_matches(["ip", "dst", "addr", DstIp|W0], W) :- 
	ip_expr_valid(DstIp),
	condition_matches(W0, W).

ip_clause_matches(["ip"|W0], W) :- 
	condition_matches(W0, W).

condition_matches(["tcp", "dst", "port", DstPort, "src", "port", SrcPort|W], W) :-
	port_expr_valid(SrcPort),
	port_expr_valid(DstPort).
condition_matches(["tcp", "dst", "port", DstPort|W], W) :-
	port_expr_valid(DstPort).
condition_matches(["tcp", "src", "port", SrcPort|W], W) :-
	port_expr_valid(SrcPort).

condition_matches(["udp", "dst", "port", DstPort, "src", "port", SrcPort|W], W) :-
	port_expr_valid(SrcPort),
	port_expr_valid(DstPort).
condition_matches(["udp", "dst", "port", DstPort|W], W) :-
	port_expr_valid(DstPort).
condition_matches(["udp", "src", "port", SrcPort|W], W) :-
	port_expr_valid(SrcPort).

condition_matches(["icmp", "type", IcmpType, "code", IcmpCode|W], W) :-
	icmp_type_expr_valid(IcmpType),
	icmp_code_expr_valid(IcmpCode).
condition_matches(["icmp", "type", IcmpType|W], W) :-
	icmp_expr_valid(IcmpType).
condition_matches(["icmp", "code", IcmpCode|W], W) :-
	icmp_expr_valid(IcmpCode).

condition_matches(W, W, _).

% Verification Functions

adpt_expr_valid(Adpt).
vid_expr_valid(Vid).
proto_expr_valid(NlProto).

ip_expr_valid(Ip) :-
	split_string(Ip, ",", IpList),
	IpList = [_,_|_],
	ip_list_expr_valid(IpList);
	split_string(Ip, "/", [Subnet, MaskStr|_]),
	ip_expr_valid(Subnet),
	number_string(Mask, MastStr),
	Mask =< 32,
	Mask >= 0;
	split_string(Ip, "-", "", [Begin, End|[]]),
	ip_expr_valid(Begin),
	ip_expr_valid(End),
	string_concat("0.0.0.0-", End, TillEnd),
	ip_expr_matches(TillEnd, Begin);
	ip_expr_matches("0.0.0.0-255.255.255.255", Ip).

ip_list_expr_valid(IpList) :-
	IpList = [H|T],
	ip_expr_valid(H),
	ip_list_expr_valid(T);
	IpList = [].

port_expr_valid(Port) :-
	split_string(Port, ",", "", PortList),
	PortList = [_,_|_],
	port_list_expr_valid(PortList);
	split_string(Port, "-", "", [Begin, End|_]),
	port_expr_valid(Begin),
	port_expr_valid(End),
	string_concat("0-", End, TillEnd),
	num_expr_matches(TillEnd, Begin);
	num_expr_matches("0-65535",Port).

port_list_expr_valid(PortList) :-
	PortList = [H|T],
	port_expr_valid(H),
	port_list_expr_valid(T);
	PortList = [].

icmp_expr_valid(Icmp) :-
	split_string(Icmp, ",", "", IcmpList),
	IcmpList = [_,_|_],
	icmp_list_expr_valid(IcmpList);
	split_string(Icmp, "-", "", [Begin, End|[]]),
	icmp_expr_valid(Begin),
	icmp_expr_valid(End),
	string_concat("0-", End, TillEnd),
	num_expr_matches(TillEnd, Begin);
	num_expr_matches("0-255", Icmp).

icmp_list_expr_valid(IcmpList) :-
	IcmpList = [H|T],
	icmp_expr_valid(H),
	icmp_list_expr_valid(T);
	IcmpList = [].

% ----------------------


% adpt_expr_matches(X, X).
adpt_expr_matches("any", _).
adpt_expr_matches(Adpt, PktAdpt) :-
	lies_in_not_Expr(Adpt, PktAdpt, false).

num_expr_matches("any", _).
num_expr_matches(NumExpr, Val):-
	lies_in_not_Expr(NumExpr, Val, true).

ip_expr_matches(_, _).


proto_expr_matches(RuleProto, PacketProto) :-
	proto_alpha_num(RuleProto, PacketProto);
	num_expr_matches(RuleProto, PacketProto).
proto_alpha_num(X, X).

% What is proto expr matches and why is it different ?
% Are empty conditions being handled ?