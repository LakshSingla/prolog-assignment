[CS F214] LOGIC IN COMPUTER SCIENCE : ASSIGNMENT (PROLOG)

Title: Implementing a firewall through prolog.

Submitted By:

Laksh Singla			2017A7PS0082P
Shubham Saxena			2017A7PS0302P

Import file 'firewall.pl' to run the program. It also contains the database of sample rules.
All other files are in the '/utils' folder.

Skip to section INSTRUCTIONS for instructions on how to use the program.

-------------------------------------------------------ABSTRACT--------------------------------------------------------

The given prolog program implements a firewall through prolog programming language.
Rules can be added to the firewall, and then packet details can be entered as queries to find out whether the packet will be accepted, rejected or ignored.


----------------------------------CONVENTION ACCEPTED FOR MULTIPLE APPLICABLE RULES-------------------------------------


Rules are evaluated top to bottom.
Earlier rules are given precedence over later rules.


---------------------------------------------REPRESENTATION OF EXPRESSIONS----------------------------------------------


Numeric expressions can be in decimal, octal or hexadecimal notation. Convention followed is same as in other languages.


	PREFIX		MEANING

	0x 			Hexadecimcal numbers
	0			Octal numbers
	None		Decimal numbers


Further, all expressions (except IPv4 expressions) can be of the following forms:
	

	TYPE 					EXAMPLE

	Single values			12

	Comma separated list	0x34,023,12
							[There should be NO SPACES in between]

	Range					72-90 (former value should be lesser than latter)
							[There should be NO SPACES in between]

	Negated 				!10-20 (matches values except 10-20 both inclusive)
							!34,70 (matches values except 34 and 70)
							[There should be NO SPACES in between]


IPv4 Expressions:

	These expressions can be written in any of the given forms:

		TYPE 						EXAMPLE

		Single						192.168.1.1

		Comma separated list		192.168.1.1,192.168.1.2

		Range						192.168.1.1-192.168.1.5

		Masked						192.168.1.1/24



---------------------------------------------------INSTRUCTIONS----------------------------------------------------------



Follow the steps to use the program -

1. 	BEGIN EXECUTION

	Import file 'firewall.pl' to prolog (All other necessary imports are handled automatically).

2. 	ADD/MODIFY FIREWALL RULES
		
	METHOD I: Through 'firewall.pl':

				Simply add/modify the rules in the firewall.pl file.

				Firewall predicates are of the form:

							fwrule(Fate, Rule).

				where,

					Fate is accept | reject | drop
					Rule is in string form, as defined in the documentation provided with assignment.

				Example:

							fwrule("accept", "ether vid any").

	METHOD II: Through queries, during runtime:

				To add your own firewall rules during execution of program, pose the following query: 
			
							?- add_fwrule(Fate, Rule).
			
				where,
				
					Fate  is accept | reject | drop
					Rule is in string form, as defined in the documentation provided with assignment.

				Example:

					fwrule("drop", "adapter A").
					[Drops all packets coming through adapter A]
			
				Example:	
					
					?- add_fwrule("accept", "adapter A ip src addr 172.27.1.3").
					[Accepts all packets coming from adapter A with source IP address 172.27.1.3]

	NOTE: Refer to pre-existing rules in 'firewall.pl' for more examples.
	NOTE: The rule language is case sensitive.
	NOTE: Clauses in the rules can be added in any order.

3. 	CHANGE FIREWALL DEFAULT
	
	Firewall default is 'drop'.

	To change firewall default during execution of the program, pose the following query:
				change_fwdefault(DefaultFate).

	Example:
				change_fwdefault("accept").
				[Changes firewall to accept packets by default]

4. 	CHECK FATE OF A PACKET

	Check the fate of any packet by asking query

				?- fate(Fate, Packet).

	where,
	
		Fate is the variable which will be instantiated to the fate of the packet (accept | reject | drop).
		Packet is a string containing the details of the packet.

		Example:

				fate(Fate, "adapter B vid 20 tlproto udp srcport 0x34 dstport 077")


		Details of a packet will include space separated key-value pairs ("Key1 Value1 Key2 Value2 ..."). 

		The following keys are defined:

			KEY						VALUE					MEANING	

			adapter					A - P					Network adapter through which packet is coming

			vid						1 - 4095 				VLAN ID (applicable for packets on 802.1q protocol)

			nlproto					0 - 255					Network layer protocol ID (optional)

			srcip					Valid IPv4 address		Source IP address

			dstip					Valid IPv4 address		Destination IP address

			tlproto					tcp | udp | icmp 		Transport layer protocol (NECESSARY in case a condition is imposed in rule)

			srcport					0 - 65535				Source port (applicable for tcp|udp)

			dstport					0 - 65535				Destination port (applicable for tcp|udp)

			icmptype				0 - 255					ICMP Type (applicable for icmp)

			icmpcode				0 - 255					ICMP Code (applicable for icmp)




---------------------------------------IMPLEMENTATION--------------------------------------------------------

The following top-level predicates exist in our program:

	1.	fwrule(+Fate, +Rule)
			Represents firewall rules in the database.

	2.	fwdefault(+DefaultFate)
			Represents firewall default in the database.

	3.	add_fwrule(+Fate, +Rule)
			Add firewall rules during runtime, first verifying if rule is valid.

	4.	change_fwdefault(+NewDefaultFate)
			Change firewall default during runtime.

	5.	fate(-Fate, +Packet)
			Check fate of a packet.

	6.	add_fwrule_noverify(+Fate, +Rule)
			Add firewall rules during runtime, without verifying if rule is valid.