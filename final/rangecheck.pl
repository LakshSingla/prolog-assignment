% Utility to check if a given value lies in a comma seperated expression, 
% where each expression can be a singleton(representing single entity) 
% or a dash seperated range. It can work on strings representing numbers (IsNum)
% or single alphabet (\+IsNum)

:- [normalize_number].

lies_in_not_Expr(MaybeNotExpr, Val, IsNum) :- 
	
	split_string(MaybeNotExpr, "!", "", ["", CSExpr]),
	\+lies_in_CS_Expr(CSExpr, Val, IsNum);

	split_string(MaybeNotExpr, "!", "", [CSExpr]),
	lies_in_CS_Expr(CSExpr, Val, IsNum).


lies_in_CS_Expr(CSExpr, Val, IsNum) :- 

	split_string(CSExpr, ",", "", L),			% split the expression by ','
	lies_in_expr(L, Val, IsNum).				% check if lies in the list obtained

lies_in_expr([H|T], Val, IsNum) :- 

	satisfies_maybe_range(H, Val, IsNum); 		% true if the value lies in the current expression
												% OR
	lies_in_expr(T, Val, IsNum).				% if the value lies in the remaining pool of expressions

satisfies_maybe_range(Expr, Val, IsNum) :- 		% The single expression can be a range or not

	split_string(Expr, "-", "", MaybeRange),	% Split by '-', if array has 1 element then it is a single entity
												% else it is a range
	satisfies(MaybeRange, Val, IsNum).

satisfies(MaybeRange, Val, IsNum) :- 

	IsNum,										% true if the user wants to compare as numbers
	MaybeRange = [Num1, Num2 | []], 			% Array has exactly 2 entities
	normalize_numstr(Num1, NNum1), 
	normalize_numstr(Num2, NNum2), 
	normalize_numstr(Val, NVal), 
	NVal >= NNum1, NVal =< NNum2; 				% Comparison

	IsNum,										% true if the user wants to compare as numbers 
	MaybeRange = [Num | []], 					% Array has exactly 1 entity
	normalize_numstr(Num, NNum), 
	normalize_numstr(Val, NVal),  
	NVal=NNum;									% Equality test

	\+IsNum, 									% true if the user wants to compare as single alphabet
	MaybeRange = [Alpha1, Alpha2 | []], 		% Array has exactly 2 entities
	Val >= Alpha1, Val =< Alpha2; 				% Comparison

	\+IsNum, 									% true if the user wants to compare as single alphabet
	MaybeRange = [Alpha | []], 					% Array has exactly 1 entity
	Val=Alpha.									% Equality
