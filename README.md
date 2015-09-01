#unicorn-decoder

A simple shellcode decoder that uses the unicorn engine as the backend to emulate a shellcode file to find self modifying code and attempt to disassemble the resulting output of the decoder stub. 

##Usage

	usage: decoder.py [-h] -f FILE [-m MODE] [-i MAX_INSTRUCTION] [-d]

	Decode supplied x86 / x64 shellcode automatically with the unicorn engine

	optional arguments:
	  -h, --help          show this help message and exit
	  -f FILE             file to shellcode binary file
	  -m MODE             mode of the emulator (32|64)
	  -i MAX_INSTRUCTION  max instructions to emulate
	  -d                  Enable extra hooks for debugging of shellcode


##Example

Here is the decoder walking through the shikata_ga_nai test case

	% python decoder.py -f testcases/shikata_ga_nai_linux_1round.bin

	Shellcode address ranges:
	   low:  0x19
	   high: 0x68

	Original shellcode:
	  0x19:	loop	0x10
	  0x1b:	xor	ebx, ebx
	  0x1d:	mul	ebx
	  0x1f:	push	ebx
	  0x20:	inc	ebx
	  0x21:	push	ebx
	  0x22:	push	2
	  0x24:	mov	ecx, esp
	  0x26:	mov	al, 0x66
	  0x28:	int	0x80
	  0x2a:	pop	ebx
	  0x2b:	pop	esi
	  0x2c:	push	edx
	  0x2d:	push	0x5c110002
	  0x32:	push	0x10
	  0x34:	push	ecx
	  0x35:	push	eax
	  0x36:	mov	ecx, esp
	  0x38:	push	0x66
	  0x3a:	pop	eax
	  0x3b:	int	0x80
	  0x3d:	mov	dword ptr [ecx + 4], eax
	  0x40:	mov	bl, 4
	  0x42:	mov	al, 0x66
	  0x44:	int	0x80
	  0x46:	inc	ebx
	  0x47:	mov	al, 0x66
	  0x49:	int	0x80
	  0x4b:	xchg	eax, ebx
	  0x4c:	pop	ecx
	  0x4d:	push	0x3f
	  0x4f:	pop	eax
	  0x50:	int	0x80
	  0x52:	dec	ecx
	  0x53:	jns	0x4d
	  0x55:	push	0x68732f2f
	  0x5a:	push	0x6e69622f
	  0x5f:	mov	ebx, esp
	  0x61:	push	eax
	  0x62:	push	ebx
	  0x63:	mov	ecx, esp
	  0x65:	mov	al, 0xb

##Limitation

Multiple rounds of any encoder will require supplying new -i counts, this can cause deadlocks with some encoders.

Only i386 right now, ARM and others will come later.

The encoder has to self modify for the detection to work, this decoder is unable to correctly detect decoded shellcode that is written to a new location in memory. 