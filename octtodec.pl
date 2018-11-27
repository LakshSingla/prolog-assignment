acc_oct([H|T], P, Dec) :- atom_number(H, Y), X is P*8+Y, acc_oct(T, X, Dec).
acc_oct([], Dec, Dec).

octtodec(OctString, DecNumber) :- acc_oct(OctString, 0, DecNumber).
