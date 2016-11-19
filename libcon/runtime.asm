BITS 32]
section .text

%ifdef ASM_EXPORT
	export  _fetch_add_c
	export  _memset
	export  _memcpy
	export  __allmul
	export  _compare_z_exchange_c
%endif

%ifdef PREFIX
	global  _fetch_add_c
	global  _memset
	global  _memcpy
	global  __allmul
	global  _compare_z_exchange_c
%else
	global  _allmul
	GLOBAL  compare_z_exchange_c:function
	GLOBAL  fetch_add_c:function
	global  memset:function
%endif


%ifdef PREFIX
_memcpy:
%else
memcpy:
%endif
   push ebp
   mov  ebp, esp
   
   push esi
   push edi
   push ecx

   mov edi, [ebp+8]   ; edi = dest
   mov esi, [ebp+12]   ; esi = src
   mov ecx, [ebp+16]   ; ecx = count
   rep movsb   ; for(i = 0; i < ecx; i++){edi[i]=esi[i]}
   pop ecx
   pop edi
   pop esi
   pop ebp
   mov eax, [ebp]      ; eax = return value = dest
ret

%ifdef PREFIX
_memset:
%else
memset:
%endif
 push ebp
    mov ebp, esp
    add ebp, 4 ; We pushed one register to stack, count it
    push ebx ; Save used registers
    push ecx
    mov eax, DWORD [ebp + 12]     ; size
    mov ecx, DWORD [ebp + 8]      ; tcx = val
    mov ebx, DWORD [ebp + 4]      ; tbx = destination

  .memset_loop:
    or eax, eax ; Fast compare to 0
    jz .aftermemset_loop
    mov [ebx], BYTE cl
    dec eax
    inc ebx
  .aftermemset_loop:
    mov eax, DWORD [ebp + 4]            ; Return destionation
    pop ecx ; Restore used registers
    pop ebx
    pop ebp

ret

%ifdef PREFIX
_compare_z_exchange_c:
%else
compare_z_exchange_c:
%endif

	push edi
	push ebx
	
	mov  edi,	[esp+12]
	mov  ebx,	[esp+16]
	
	sfence
	
	;Compare EAX with r/m32. If equal, ZF is set and r32 is	 loaded into r/m32. Else, clear ZF and load r/m32 into AL
	
	xor	eax				,	eax
	lock CMPXCHG [edi]	,	ebx
	jnz _compare_z_exchange_c_not_changed
		mov eax,1
		jmp _compare_z_exchange_c_done
	_compare_z_exchange_c_not_changed:
		xor eax,eax
	 
	_compare_z_exchange_c_done:
	pop ebx
	pop edi
ret

%ifdef PREFIX
_fetch_add_c:
%else
fetch_add_c:
%endif
	push edi
	mov  edi,	[esp+8]
	mov  eax,	[esp+12]
	lock xadd [edi]	, eax
	pop edi
ret



