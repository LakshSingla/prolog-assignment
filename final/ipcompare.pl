% Compare two ip addresses in prolog.

% IP may be of the following forms:
%	List
%	Range
%	Masked
%	Single

% ip_expr_matches(+RuleIPString, +PacketIPString)

ip_expr_matches(RuleIP, PacketIP) :-
	split_string(RuleIP, ",", "", IPList),
	IPList = [_,_|_],
	ip_list_expr_matches(IPList, PacketIP),
	!;
	split_string(RuleIP, "-", "", IPRange),
	IPRange = [Begin,End|_],
	ip_to_binary(Begin, BeginBinaryStr),
	number_string(BeginBinary, BeginBinaryStr),
	ip_to_binary(End, EndBinaryStr),
	number_string(EndBinary, EndBinaryStr),
	ip_to_binary(PacketIP, PacketBinaryStr),
	number_string(PacketBinary, PacketBinaryStr),
	!,
	BeginBinary =< PacketBinary,
	EndBinary >= PacketBinary;
	split_string(RuleIP, "/", "", [Subnet|MaskList]),
	MaskList = [MaskStr|_],
	number_string(Mask, MaskStr),
	ip_to_binary(Subnet, SubnetBinary),
	ip_to_binary(PacketIP, PacketIpBinary),
	masked_compare(SubnetBinary, PacketIpBinary, Mask),
	!;
	ip_to_binary(RuleIP, Ip),
	ip_to_binary(PacketIP, Ip).

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
	split_string(IP, ".", "", [ADecimal,BDecimal,CDecimal,DDecimal|_]),
	decimal_to_byte(ADecimal, A),
	decimal_to_byte(BDecimal, B),
	decimal_to_byte(CDecimal, C),
	decimal_to_byte(DDecimal, D),
	string_concat(A, B, AB),
	string_concat(AB, C, ABC),
	string_concat(ABC, D, IPBinary).