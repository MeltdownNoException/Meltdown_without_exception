This project can achieve meltdown attacks without execeptions.

When implementing the project, we referred to the following three project:

https://github.com/IAIK/meltdown

https://github.com/paboldin/meltdown-exploit

Paul Kocher, Daniel Genkin, Daniel Gruss, Werner Haas, Mike Hamburg, Moritz Lipp, Stefan Mangard, Thomas Prescher, Michael Schwarz, and Yuval Yarom. 2018. Spectre Attacks: Exploiting Speculative Execution. arXiv preprint arXiv:1801.01203 (2018).


Build:

	You can build the project by the following command:
	
	make
	
Run:

	The secret is a program that store a string into kernel address.
	
	The meltdown is a program that steals secret data according to the input data address. It need two parameters, one is the address of data you wanted, and the other is how many bytes you want to qcquire.
	
	You can type 
	
		sudo ./secret 
		
	to run the secret program. The output gives the string that is stored into the kernel space and the address of the string.
	Then, you can input
	
		./meltdown address size
		
	to steal the string.
