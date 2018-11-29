% Compare two ip addresses in prolog.

% IP may be of the following forms:
%	List
%	Range
%	Masked
%	Single

ip_expr_matches(RuleIP, PacketIP) :-

	split_string(RuleIP, ",", "", IPList),
	IPList = [_,_|_],
	ip_list_expr_matches(IPList, PacketIP),
	!
	;

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
	EndBinary >= PacketBinary
	;

	split_string(RuleIP, "/", "", [Subnet|MaskList]),
	MaskList = [MaskStr|_],
	number_string(Mask, MaskStr),
	ip_to_binary(Subnet, SubnetBinary),
	ip_to_binary(PacketIP, PacketIpBinary),
	mask_compare(SubnetBinary, PacketIpBinary, Mask)
	;

	ip_to_binary(RuleIP, Ip),
	ip_to_binary(PacketIP, Ip).

ip_list_expr_matches([Head|Tail], PacketIP) :-
	ip_expr_matches(Head, PacketIP);
	ip_list_expr_matches(Tail, PacketIP).

ip_to_binary(Ip, IpBin) :-
	split_string(Ip, ".", "", [ADecimal,BDecimal,CDecimal,DDecimal|_]),
	decimal_to_byte(ADecimal, A),
	decimal_to_byte(BDecimal, B),
	decimal_to_byte(CDecimal, C),
	decimal_to_byte(DDecimal, D),
	string_concat(A, B, AB),
	string_concat(AB, C, ABC),
	string_concat(ABC, D, IpBin).

decimal_to_byte(NumStr, ByteStr) :-
	number_string(Num, NumStr),
	decimal_to_binary(Num, BinStr),
	!,
	equivalent_byte(BinStr, ByteStr).

decimal_to_binary(1, "1").
decimal_to_binary(0, "0").
decimal_to_binary(Decimal, Binary) :-
	Remainder is Decimal mod 2,
	number_string(Remainder, RemainderStr),
	Quotient is Decimal // 2,
	decimal_to_binary(Quotient, QBinary),
	string_concat(QBinary, RemainderStr, Binary).

equivalent_byte(Binary, Byte) :-

	string_length(Binary, 8),
	Binary = Byte,
	!;

	string_length(Binary, Length),
	Length < 8,
	string_concat("0", Binary, NewBinary),
	equivalent_byte(NewBinary, Byte).

mask_compare(Subnet, PacketIP, Mask) :-
	string_concat(SubPre, _, Subnet),
	string_length(SubPre, Mask),
	string_concat(PacketPre, _, PacketIP),
	string_length(PacketPre, Mask),
	SubPre = PacketPre,
	!
	.
