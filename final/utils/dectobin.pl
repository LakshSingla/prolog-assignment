:- module(dectobin, [decimal_to_byte/2]).

% decimal_to_byte(+DecimalString, -ByteString)

decimal_to_byte(Decimal, Byte) :-					% Converts a number into binary byte form (bit string of length 8)
	number_string(Number, Decimal),
	decimal_to_binary(Number, Binary),
	!,
	equivalent_byte(Binary, Byte).


% decimal_to_binary(+DecimalNumber, -BinaryString)

decimal_to_binary(1, "1").
decimal_to_binary(0, "0").
decimal_to_binary(Decimal, Binary) :-				% Converts a number into binary form
	Remainder is Decimal mod 2,
	Quotient is Decimal // 2,
	decimal_to_binary(Quotient, QuotientBinary),
	string_concat(QuotientBinary, Remainder, Binary).


% equivalent_byte(+BinaryString, -ByteString)

equivalent_byte(Binary, Byte) :-					% Appends 0s until bit string equals length 8
	string_length(Binary, 8),
	Binary = Byte,
	!;
	string_length(Binary, Length),
	Length < 8,
	string_concat("0", Binary, BinaryExtended),
	equivalent_byte(BinaryExtended, Byte).