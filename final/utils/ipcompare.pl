% Compare two ip addresses in prolog.

% IP may be of the following forms:
%	List
%	Range
%	Masked
%	Single

:- module(ipcompare, [ip_expr_matches/2]).
% :- ensure_loaded([dectobin]).
:- use_module(dectobin, [decimal_to_byte/2]).
:- use_module(rangecheck, [num_expr_matches/2]).
:- use_module(normalize_number, [normalize_numstr/2]).

% ip_expr_matches(+RuleIPString, +PacketIPString)

ip_expr_matches("any", _).

ip_expr_matches(RuleIP, PacketIP) :-
	split_string(RuleIP, ",", "", IPList),				% for when IP is a list
	IPList = [_,_|_],
	ip_list_expr_matches(IPList, PacketIP),
	!;
	split_string(RuleIP, "-", "", [Begin, End]),		% for when IP is a range
	split_string(Begin, ".", "", BeginList),
	split_string(End, ".", "", EndList),
	split_string(PacketIP, ".", "", PacketList),
	BeginList = [_,_,_,_],
	EndList = [_,_,_,_],
	PacketList = [_,_,_,_],
	ip_list_expr_ascending(BeginList, PacketList),
	ip_list_expr_ascending(PacketList, EndList),
	!;
	split_string(RuleIP, "/", "", [Subnet,MaskStr]),	% for when IP is in masked form
	normalize_numstr(MaskStr, Mask),
	ip_to_binary(Subnet, SubnetBinary),
	ip_to_binary(PacketIP, PacketIpBinary),
	masked_compare(SubnetBinary, PacketIpBinary, Mask),
	!;
	split_string(RuleIP, ".", "", [R1,R2,R3,R4]),		% for when IP is a single value
	split_string(PacketIP, ".", "", [P1,P2,P3,P4]),
	num_expr_matches(R1, P1),
	num_expr_matches(R2, P2),
	num_expr_matches(R3, P3),
	num_expr_matches(R4, P4),
	!.

% ip_list_expr_ascending(+ListOfStringNumbers, +ListOfStringNumbers) : checks if corresponsing elements of two lists containing strings of numbers are in ascending order.

ip_list_expr_ascending(X, Y) :-
	X = [Xh|Xt],
	Y = [Yh|Yt],
	string_concat("0-", Yh, TillYh),
	num_expr_matches(TillYh, Xh),
	ip_list_expr_ascending(Xt, Yt);
	X = [],
	Y = [].

% ip_list_expr_matches(+IPList, +PacketIP)

ip_list_expr_matches([Head|Tail], PacketIP) :-
	ip_expr_matches(Head, PacketIP);
	ip_list_expr_matches(Tail, PacketIP).

% masked_compare(+IPBinaryString, +PacketIPBinaryString, +MaskNumber)

masked_compare(Subnet, PacketIP, Mask) :-
	string_concat(SubnetPrefix, _, Subnet),				% extract first 'Mask' bits from binary form of IP
	string_length(SubnetPrefix, Mask),
	string_concat(PacketPrefix, _, PacketIP),
	string_length(PacketPrefix, Mask),
	!,
	SubnetPrefix = PacketPrefix.

% ip_to_binary(+IPString, -BinaryIPString)

ip_to_binary(IP, IPBinary) :-
	split_string(IP, ".", "", [AStr,BStr,CStr,DStr]),
	normalize_numstr(AStr, ADecNum),					% normalize numbers
	normalize_numstr(BStr, BDecNum),
	normalize_numstr(CStr, CDecNum),
	normalize_numstr(DStr, DDecNum),
	number_string(ADecNum, ADecStr),					% convert numbers to string
	number_string(BDecNum, BDecStr),
	number_string(CDecNum, CDecStr),
	number_string(DDecNum, DDecStr),
	decimal_to_byte(ADecStr, A),						% convert numbers to byte
	decimal_to_byte(BDecStr, B),
	decimal_to_byte(CDecStr, C),
	decimal_to_byte(DDecStr, D),
	string_concat(A, B, AB),
	string_concat(AB, C, ABC),
	string_concat(ABC, D, IPBinary).					% concatenate all bytes