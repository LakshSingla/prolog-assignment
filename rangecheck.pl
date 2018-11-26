liesInCSExpr(CSExpr, Val) :- split_string(CSExpr, ",", "", L), liesInExpr(L, Val). 

liesInExpr([H|T], Val) :- satisfiesMaybeRange(H, Val); liesInExpr(T, Val).

satisfiesMaybeRange(Expr, Val) :- split_string(Expr, "-", "", MaybeRange), satisfies(MaybeRange, Val).

satisfies(MaybeRange, Val) :- 
	MaybeRange = [R1, R2 | []], number_string(NR1, R1), number_string(NR2, R2), Val >= NR1, Val =< NR2; 
	MaybeRange = [TestVal | []], number_string(NTestVal, TestVal), Val=NTestVal.
