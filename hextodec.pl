% Utility to convert a hexadecimal string into its equivalent decimal representation

% Numerical forms of the hexadecimal atoms
hexdigtodec('0', 0).
hexdigtodec('1', 1).
hexdigtodec('2', 2).
hexdigtodec('3', 3).
hexdigtodec('4', 4).
hexdigtodec('5', 5).
hexdigtodec('6', 6).
hexdigtodec('7', 7).
hexdigtodec('8', 8).
hexdigtodec('9', 9).
hexdigtodec('A', 10).
hexdigtodec('B', 11).
hexdigtodec('C', 12).
hexdigtodec('D', 13).
hexdigtodec('E', 14).
hexdigtodec('F', 15).

acc_hex([H|T], P, Dec) :- 					

	hexdigtodec(H, Y), 						% Convert the character into numeral
	X is P*16+Y, 							% curval = pastval*16 +  curdigit
	acc_hex(T, X, Dec).						% Continue accumulating

acc_hex([], Dec, Dec).						% Transfer on bottoming out

% hextodec(HexString, DecNumber) :- 

	% atom_string(HexAtomic, HexString), 		% Convert the string to equivalent atom
	% atom_chars(HexAtomic, HexAtomicArr), 	% Split the atom into characters
	% acc_hex(HexAtomicArr, 0, DecNumber).	% Call the hex accumulator on the char array
