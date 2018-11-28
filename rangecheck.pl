lies_in_CS_Expr(CSExpr, Val, IsNum) :- split_string(CSExpr, ",", "", L), lies_in_expr(L, Val, IsNum). 

lies_in_expr([H|T], Val, IsNum) :- satisfies_maybe_range(H, Val, IsNum); lies_in_expr(T, Val, IsNum).

satisfies_maybe_range(Expr, Val, IsNum) :- split_string(Expr, "-", "", MaybeRange), satisfies(MaybeRange, Val, IsNum).

satisfies(MaybeRange, Val, IsNum) :- 
	IsNum, MaybeRange = [Num1, Num2 | []], number_string(NNum1, Num1), number_string(NNum2, Num2), number_string(NVal, Val), NVal >= NNum1, NVal =< NNum2; 
	IsNum, MaybeRange = [Num | []], number_string(NNum, Num), number_string(NVal, Val),  NVal=NNum;
	\+IsNum, MaybeRange = [Alpha1, Alpha2 | []], Val >= Alpha1, Val =< Alpha2; 
	\+IsNum, MaybeRange = [Alpha | []], Val=Alpha.
