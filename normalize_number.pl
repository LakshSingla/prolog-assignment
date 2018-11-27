:- [octtodec, hextodec].

normalize_numstr(NumString, NormalizedNum) :- 
	atom_string(NumAtomic, NumString), atom_chars(NumAtomic, NumAtomicArr), normalize_numatomicarr(NumAtomicArr, NormalizedNum).

normalize_numatomicarr(NumAtomicArr, NormalizedNum) :-
	NumAtomicArr = ['0', 'x'| HexAtomicArr], acc_hex(HexAtomicArr, 0, NormalizedNum);
	NumAtomicArr = ['0'| OctAtomicArr], acc_oct(OctAtomicArr, 0, NormalizedNum).
