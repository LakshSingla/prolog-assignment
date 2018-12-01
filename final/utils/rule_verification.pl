% Header imports

% :- [parser].

:- module(rule_verification, [verify_fate/1, verify_fwrule/1]).

:- use_module(ipcompare, [ip_expr_matches/2]).
:- use_module(rangecheck, [num_expr_matches/2, adpt_expr_matches/2]).

% :- ensure_loaded([ipcompare, rangecheck]).

% Predicate to verify fate is a valid expression

verify_fate(Fate) :-
	Fate = "accept";
	Fate = "reject";
	Fate = "drop".

% Predicate to verify that rule is a valid expression

verify_fwrule(RuleStr) :- 
	split_string(RuleStr, " ", "", Rule),
	catch(rule_parser(Rule, []), _, false),
	!.

% Grammar for firewall rules

rule_parser(X, Y) :- clause_parser(X, Y).
rule_parser(X, Y) :- clause_parser(X, Z), rule_parser(Z, Y).

clause_parser(X, Y) :- 
		adpt_clause_matches(X, Y);
		eth_clause_matches(X, Y);
		ip_clause_matches(X, Y).

% ---------------------Definition of specific clauses--------------------

% Adapter clause

adpt_clause_matches(["adapter", Adpt|W], W) :- 
	adpt_expr_valid(Adpt).

% Ethernet clause

eth_clause_matches(["ether", "vid", Vid, "proto", NlProto|W], W) :- 				% Ethernet clause with both VID and protocol
	vid_expr_valid(Vid),
	proto_expr_valid(NlProto).
eth_clause_matches(["ether", "vid", Vid|W], W) :-									% Ethernet clause with only VID
	vid_expr_valid(Vid).
eth_clause_matches(["ether", "proto", NlProto|W], W) :-								% Ethernet clause with only protocol
	proto_expr_valid(NlProto).

% IP clause

ip_clause_matches(["ip", "src", "addr", SrcIp, "dst", "addr", DstIp|W0], W) :- 		% IP clause with src addr and dst addr (& tcp | udp conditions)
	ip_expr_valid(SrcIp),
	ip_expr_valid(DstIp),
	condition_matches(W0, W).

ip_clause_matches(["ip", "addr", Ip|W0], W) :- 										% IP clause with only addr (& tcp | udp conditions)
	ip_expr_valid(Ip),
	condition_matches(W0, W).

ip_clause_matches(["ip", "src", "addr", SrcIp|W0], W) :- 							% IP clause with only src addr (& tcp | udp conditions)
	ip_expr_valid(SrcIp),
	condition_matches(W0, W).

ip_clause_matches(["ip", "dst", "addr", DstIp|W0], W) :- 							% IP clause with only dst addr (& tcp | udp conditions)
	ip_expr_valid(DstIp),
	condition_matches(W0, W).

ip_clause_matches(["ip"|W0], W) :- 													% Empty IP clause (& tcp | udp conditions)
	condition_matches(W0, W).

% Conditions for tcp

condition_matches(["tcp", "dst", "port", DstPort, "src", "port", SrcPort|W], W) :-	% TCP condition with src port and dst port
	port_expr_valid(SrcPort),
	port_expr_valid(DstPort).
condition_matches(["tcp", "dst", "port", DstPort|W], W) :-							% TCP conditions with only dst port
	port_expr_valid(DstPort).
condition_matches(["tcp", "src", "port", SrcPort|W], W) :-							% TCP conditions with only src port
	port_expr_valid(SrcPort).

% Conditions for udp

condition_matches(["udp", "dst", "port", DstPort, "src", "port", SrcPort|W], W) :-	% UDP conditions with src port and dst port
	port_expr_valid(SrcPort),
	port_expr_valid(DstPort).
condition_matches(["udp", "dst", "port", DstPort|W], W) :-							% UDP conditions with only dst port
	port_expr_valid(DstPort).
condition_matches(["udp", "src", "port", SrcPort|W], W) :-							% UDP conditions with only src port
	port_expr_valid(SrcPort).

% Conditions for icmp

condition_matches(["icmp", "type", IcmpType, "code", IcmpCode|W], W) :-				% ICMP conditions with Type and Code
	icmp_expr_valid(IcmpType),
	icmp_expr_valid(IcmpCode).
condition_matches(["icmp", "type", IcmpType|W], W) :-								% ICMP conditions with only Type
	icmp_expr_valid(IcmpType).
condition_matches(["icmp", "code", IcmpCode|W], W) :-								% ICMP conditions with only Code
	icmp_expr_valid(IcmpCode).

condition_matches(W, W).															% Empty conditions

% --------------------Verification Functions-----------------------

% Verification of adapter expression

adpt_expr_valid(Adpt) :-
	split_string(Adpt, "!", "", ["", AdptNegated]),					% Negated adapter expressions
	adpt_expr_valid(AdptNegated);
	split_string(Adpt, ",", "", AdptList),							% List adapter expressions
	AdptList = [_,_|_],
	adpt_list_expr_valid(AdptList);
	split_string(Adpt, "-", "", [Begin, End]),						% Range adapter expressions
	adpt_expr_valid(Begin),
	adpt_expr_valid(End),
	string_concat("A-", End, TillEnd),
	adpt_expr_matches(TillEnd, Begin);
	adpt_expr_matches("A-P",Adpt).									% Single adapter expressions

% Verification of list of adapter expressions

adpt_list_expr_valid(AdptList) :-
	AdptList = [H|T],
	adpt_expr_valid(H),
	adpt_list_expr_valid(T);
	AdptList = [].

% Verification of VID expressions

vid_expr_valid(Vid) :-
	split_string(Vid, "!", "", ["", VidNegated]),					% Negated VID expressions
	vid_expr_valid(VidNegated);
	split_string(Vid, ",", "", VidList),							% List VID expressions
	VidList = [_,_|_],
	vid_list_expr_valid(VidList);
	split_string(Vid, "-", "", [Begin, End]),						% Range VID expressions
	vid_expr_valid(Begin),
	vid_expr_valid(End),
	string_concat("1-", End, TillEnd),
	num_expr_matches(TillEnd, Begin);
	num_expr_matches("1-4095", Vid).								% Single VID expressions

% Verification of list of VID expressions

vid_list_expr_valid(VidList) :-
	VidList = [H|T],
	vid_expr_valid(H),
	vid_list_expr_valid(T);
	VidList = [].

% Verification of protocol ID (same as verification of VID, since the range is same)

proto_expr_valid(NlProto) :-
	icmp_expr_valid(NlProto).

% Verification of IP expressions

ip_expr_valid(Ip) :-
	split_string(Ip, ",", "", IpList),								% List IP expressions
	IpList = [_,_|_],
	ip_list_expr_valid(IpList);
	split_string(Ip, "/", "", [Subnet, Mask]),						% Masked IP expressions
	ip_expr_valid(Subnet),
	num_expr_matches("0-32", Mask);
	split_string(Ip, "-", "", [Begin, End]),						% Range IP expressions
	ip_expr_valid(Begin),
	ip_expr_valid(End),
	string_concat("0.0.0.0-", End, TillEnd),
	ip_expr_matches(TillEnd, Begin);
	ip_expr_matches("0.0.0.0-255.255.255.255", Ip).					% Single IP expressions

% Verification of list of IP expressions

ip_list_expr_valid(IpList) :-
	IpList = [H|T],
	ip_expr_valid(H),
	ip_list_expr_valid(T);
	IpList = [].

% Verification of port expressions for tcp | udp

port_expr_valid(Port) :-
	split_string(Port, "!", "", ["", PortNegated]),					% Negated port expressions
	port_expr_valid(PortNegated);
	split_string(Port, ",", "", PortList),							% List port expressions
	PortList = [_,_|_],
	port_list_expr_valid(PortList);
	split_string(Port, "-", "", [Begin, End]),						% Range port expressions
	port_expr_valid(Begin),
	port_expr_valid(End),
	string_concat("0-", End, TillEnd),
	num_expr_matches(TillEnd, Begin);
	num_expr_matches("0-65535",Port).								% Single port expressions

% Verification of list of port expressions for tcp | udp

port_list_expr_valid(PortList) :-
	PortList = [H|T],
	port_expr_valid(H),
	port_list_expr_valid(T);
	PortList = [].

% Verification of ICMP Type | Code Expressions

icmp_expr_valid(Icmp) :-
	split_string(Icmp, "!", "", ["", IcmpNegated]),					% Negated ICMP expressions
	icmp_expr_valid(IcmpNegated);
	split_string(Icmp, ",", "", IcmpList),							% List ICMP expressions
	IcmpList = [_,_|_],
	icmp_list_expr_valid(IcmpList);
	split_string(Icmp, "-", "", [Begin, End]),						% Range ICMP expressions
	icmp_expr_valid(Begin),
	icmp_expr_valid(End),
	string_concat("0-", End, TillEnd),
	num_expr_matches(TillEnd, Begin);
	num_expr_matches("0-255", Icmp).								% Single ICMP expressions

% Verification of list of ICMP Type | Code expressions

icmp_list_expr_valid(IcmpList) :-
	IcmpList = [H|T],
	icmp_expr_valid(H),
	icmp_list_expr_valid(T);
	IcmpList = [].

% ---------------------------------------------------
