% Utility to convert a string representation of a number into equivalent decimal representation
% It detects the string to be hexadecimal if it begins with "0x" or "0X"
% It detects the string to be octal if it begins with "0"
% It defaults to decimal in all other cases and return false if the string is not a valid
% numerical representation

:- module(normalize_number, [normalize_numstr/2]).

:- use_module(hextodec, [acc_hex/3]).
:- use_module(octtodec, [acc_oct/3]).

% :- ensure_loaded([octtodec, hextodec]).


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
