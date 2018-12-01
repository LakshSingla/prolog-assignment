:- module(firewall, [add_fwrule/2, change_fwdefault/1, fate/2, add_fwrule_noverify/2]).

:- use_module(parser, [verify_fate/1, verify_fwrule/1, fwrule_matches/2]).

:- dynamic fwrule/2.
:- dynamic fwdefault/1.

% -----------------------------FIREWALL RULES DATABASE-----------------------------------

fwrule("reject","adapter any ip src addr any dst addr 0xC0.0xA8.0x1.0x1").						% IPv4 is hex equivalent of 192.168.1.1
fwrule("reject","adapter any ip src addr any dst addr any icmp type 010").						% ICMP type octal equivalent of 8
fwrule("accept","adapter A ip src addr !172.11.1.1-172.11.1.10 dst addr any tcp src port 20 dst port 80").
fwrule("drop","adapter A ip src addr 168.25.5.1/24").
fwrule("drop", "adapter A ip addr 192.168.1.1").
fwrule("reject", "adapter M,O ether vid 20").
fwrule("accept", "adapter K").











fwdefault("drop").


% ---------------------------------------------------------------------------------------

add_fwrule(Fate, Rule) :-
	verify_fate(Fate),
	verify_fwrule(Rule), 
	assertz(fwrule(Fate, Rule)),
	!;
	\+ write("Please enter a valid firewall rule.").

change_fwdefault(DefaultFate) :- 
	verify_fate(DefaultFate),
	retractall(firewall:fwdefault(_)), 
	assertz(fwdefault(DefaultFate)),
	!.

fate(Fate, PacketStr) :- 
	fwrule(Fate, RuleStr),
	split_string(RuleStr, " ", "", Rule),
	split_string(PacketStr, " ", "", Packet),
	fwrule_matches(Rule, Packet),
	write("MATCHES: "),
	write(RuleStr),
	!.

fate(Fate, _) :- write("Resorting to firewall default"), fwdefault(Fate).

add_fwrule_noverify(Fate, Rule) :-
	assertz(fwrule(Fate, Rule)).