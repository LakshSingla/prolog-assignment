% Compare two ip addresses in prolog.

% IP may be of the following forms:
%	List
%	Range
%	Masked
%	Single

% ip_expr_matches(+RuleIPString, +PacketIPString)
:- module(ipcompare, [ip_expr_matches/2]).
% :- ensure_loaded([dectobin]).
:- use_module(dectobin, [decimal_to_byte/2]).
:- use_module(rangecheck, [num_expr_matches/2]).


ip_expr_matches(RuleIP, PacketIP) :-
	split_string(RuleIP, ",", "", IPList),
	IPList = [_,_|_],
	ip_list_expr_matches(IPList, PacketIP),
	!;
	split_string(RuleIP, "-", "", [Begin, End|[]]),
	split_string(Begin, ".", "", [B1,B2,B3,B4|[]]),
	split_string(End, ".", "", [E1,E2,E3,E4|[]]),
	split_string(PacketIP, ".", "", [P1,P2,P3,P4|[]]),
	string_numbers_ascending(B1, P1),
	string_numbers_ascending(B2, P2),
	string_numbers_ascending(B3, P3),
	string_numbers_ascending(B4, P4),
	string_numbers_ascending(P1, E1),
	string_numbers_ascending(P2, E2),
	string_numbers_ascending(P3, E3),
	string_numbers_ascending(P4, E4),
	!;
	split_string(RuleIP, "/", "", [Subnet,MaskStr|[]]),
	number_string(Mask, MaskStr),
	ip_to_binary(Subnet, SubnetBinary),
	ip_to_binary(PacketIP, PacketIpBinary),
	masked_compare(SubnetBinary, PacketIpBinary, Mask),
	!;
	split_string(RuleIP, ".", "", [R1,R2,R3,R4|[]]),
	split_string(PacketIP, ".", "", [P1,P2,P3,P4|[]]),
	string_numbers_equal(R1, P1),
	string_numbers_equal(R2, P2),
	string_numbers_equal(R3, P3),
	string_numbers_equal(R4, P4).

% string_numbers_equal(+StringNumber, +StringNumber) : checks if two numbers (stored as strings) are equal.

string_numbers_equal(X, Y) :-
	number_string(NumX, X),
	number_string(NumY, Y),
	NumX = NumY.

% string_numbers_ascending(+StringNumber, +StringNumber) : checks if two numbers (stored as strings) are in ascending order.

string_numbers_ascending(X, Y) :-
	number_string(NumX, X),
	number_string(NumY, Y),
	NumX =< NumY.

% ip_list_expr_matches(+IPList, +PacketIP)

ip_list_expr_matches([Head|Tail], PacketIP) :-
	ip_expr_matches(Head, PacketIP);
	ip_list_expr_matches(Tail, PacketIP).

% masked_compare(+IPBinaryString, +PacketIPBinaryString, +MaskNumber)

masked_compare(Subnet, PacketIP, Mask) :-
	string_concat(SubnetPrefix, _, Subnet),
	string_length(SubnetPrefix, Mask),
	string_concat(PacketPrefix, _, PacketIP),
	string_length(PacketPrefix, Mask),
	!,
	SubnetPrefix = PacketPrefix.

% ip_to_binary(+IPString, -BinaryIPString)

ip_to_binary(IP, IPBinary) :-
	split_string(IP, ".", "", [ADecimal,BDecimal,CDecimal,DDecimal|[]]),
	decimal_to_byte(ADecimal, A),
	decimal_to_byte(BDecimal, B),
	decimal_to_byte(CDecimal, C),
	decimal_to_byte(DDecimal, D),
	string_concat(A, B, AB),
	string_concat(AB, C, ABC),
	string_concat(ABC, D, IPBinary).