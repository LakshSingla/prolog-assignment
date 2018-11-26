check_fate(Object) :- rule(Rule), check_compatibility(Rule, Object).

check_compatibility(Rule, Object) :- rule_parser(Rule, [], Object).

rule_parser(R1, R2, O) :- clause_parser(R1, R2, O).
rule_parser(R1, R2, O) :- clause_parser(R1, R3, O), rule_parser(R3, R2, O).

clause_parser(["color",C|L],L,O) :- get_color(O, Oc), C=Oc.
clause_parser(["shape",S|L],L,O) :- get_shape(O, Os), S=Os.
clause_parser(["music",M|L],L,O) :- get_music(O, Om), M=Om.

get_color(["color",Oc|_], Oc).
get_color([_|L], Oc) :- get_color(L, Oc).

get_shape(["shape",Os|_], Os).
get_shape([_|L], Os) :- get_shape(L, Os).

get_music(["music",Om|_], Om).
get_music([_|L], Om) :- get_music(L, Om).

rule(["color","A","shape","D"]).
rule(["music","G"]).
