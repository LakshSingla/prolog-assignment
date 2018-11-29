acc_oct([H|T], P, Dec) :- 
    
    atom_number(H, Y),      % Convert the character into numeral
    X is P*8+Y,             % curval = pastval*8 +  curdigit
    acc_oct(T, X, Dec).     % Continue accumulating

acc_oct([], Dec, Dec).      % Transfer on bottoming out

% octtodec(OctString, DecNumber) :- 
    % atom_string(OctAtomic, OctString),
    % atom_chars(OctAtomic, OctAtomicArr),
    % acc_oct(OctAtomicArr, 0, DecNumber).