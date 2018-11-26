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

acc_hex([H|T], P, Dec) :- hexdigtodec(H, Y), X is P*16+Y, acc_hex(T, X, Dec).
acc_hex([], Dec, Dec).

hextodec(Hex, Dec) :- string_chars(Hex, L), acc_hex(L, 0, Dec).
