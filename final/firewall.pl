:- module(firewall, [add_fwrule/2, change_fwdefault/1, fate/2, add_fwrule_noverify/2]).

:- use_module('utils/parser', [verify_fate/1, verify_fwrule/1, fwrule_matches/2]).

:- dynamic fwrule/2.
:- dynamic fwdefault/1.

% -----------------------------FIREWALL RULES DATABASE-----------------------------------


fwrule("accept", "adapter A").
fwrule("drop", "adapter A ip addr 192.168.1.1").
fwrule("reject", "adapter !B ether vid 20").










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
	write(RuleStr),
	!.

add_fwrule_noverify(Fate, Rule) :-
	assertz(fwrule(Fate, Rule)).