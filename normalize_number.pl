:- [octtodec, hextodec].

normalize_numstr(NumString, NormalizedNum) :- 

	atom_string(NumAtomic, NumString), 					% Convert string to atom
	atom_chars(NumAtomic, NumAtomicArr), 				% Split the atom into constituent chars
	normalize_numatomicarr(NumAtomicArr, NormalizedNum).% Pass to normalization of array

normalize_numatomicarr(NumAtomicArr, NormalizedNum) :-

	NumAtomicArr = ['0', 'x'| HexAtomicArr], 			% Detect if hex
	acc_hex(HexAtomicArr, 0, NormalizedNum);			% Pass to hex accumulator the rest of the array

	NumAtomicArr = ['0', 'X'| HexAtomicArr], 			% Detect if hex
	acc_hex(HexAtomicArr, 0, NormalizedNum);			% Pass to hex accumulator the rest of the array

	NumAtomicArr = ['0'| OctAtomicArr], 				% Detect if oct
	acc_oct(OctAtomicArr, 0, NormalizedNum);			% Pass to oct accumulator the rest of the array

	atom_chars(NumAtomic, NumAtomicArr), 				% Defaults to decimal
	atom_number(NumAtomic, NormalizedNum).				% Would return false if the number can't be converted into
														% decimal representation, else returns the decimal representation