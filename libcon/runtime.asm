BITS 32]
section .text


%ifdef ASM_EXPORT
	export  _fetch_add_c
	export  _memset
	export  _memcpy
	export  _compare_z_exchange_c

	export _libc_sind
	export _libc_cosd
	export _libc_sqrtd
	export _libc_atand
	export _libc_sinf
	export _libc_cosf
	export _libc_atanf
	export _libc_ftol
	export _libc_ftouc
%endif

%ifdef PREFIX
	global  _fetch_add_c
	global  _memset_asm
	global  _memcpy_asm
	global  _compare_z_exchange_c

	global _libc_sind
	global _libc_cosd
	global _libc_sqrtd
	global _libc_atand
	global _libc_sinf
	global _libc_cosf
	global _libc_atanf
	global _libc_ftol
	global _libc_ftouc


%else
	GLOBAL  fetch_add_c:function 
	global  memset_asm:function
	global  memcpy_asm:function
	GLOBAL  compare_z_exchange_c:function
	
	global libc_sind:function
	global libc_cosd:function
	global libc_sqrtd:function
	global libc_atand:function
	global libc_sinf:function
	global libc_cosf:function
	global libc_atanf:function
	global libc_ftol:function
	global _libc_ftouc:function
%endif


%ifdef PREFIX
_memcpy_asm:
%else
memcpy_asm:
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
_memset_asm:
%else
memset_asm:
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




;----------------
;double
;----------------
%ifdef PREFIX
_libc_sqrtd:
%else
libc_sqrtd:
%endif
	fld qword [esp+4]
	fsqrt
	mov eax,dword [esp+12]
	fstp qword [eax]
ret


%ifdef PREFIX
_libc_sind:
%else
libc_sind:
%endif
	fld qword [esp+4]
	fsin
	mov eax,dword [esp+12]
	fstp qword[eax]
ret

%ifdef PREFIX
_libc_cosd:
%else
libc_cosd:
%endif

	fld qword [esp+4]
	fcos
	mov eax,dword [esp+12]
	fstp qword[eax]
ret

%ifdef PREFIX
_libc_atand:
%else
libc_atand:
%endif
	fld qword [esp+4]
    fld1 	
	fpatan
	mov eax,dword [esp+12]
	fstp qword [eax]
ret




;----------------
;float
;----------------
%ifdef PREFIX
_libc_sinf:
%else
libc_sinf:
%endif
	fld dword [esp+4]
	fsin
ret

%ifdef PREFIX
_libc_cosf:
%else
libc_cosf:
%endif
	fld dword [esp+4]
	fcos
ret

%ifdef PREFIX
_libc_atanf:
%else
libc_atanf:
%endif
	fld dword [esp+4]
    fld1 	
	fpatan
ret

%ifdef PREFIX
_libc_ftol:
%else
libc_ftol:
%endif
	fld dword [esp+4]
	mov eax,dword [esp+8]
	fistp dword [eax]
ret

%ifdef PREFIX
_libc_ftouc:
%else
libc_ftouc:
%endif
	fld   dword [esp+4]
	fistp dword [esp-4]
	cmp dword [esp-4],255
	jl inf_255
		mov   al,255
	ret
	inf_255:
		mov   al,byte [esp-4]
ret


%define a               QWORD [ebp+8]
%define b               QWORD [ebp+16]
%define result          DWORD [ebp+24]
%define ctrlWord            WORD [ebp-2]
%define tmp             DWORD [ebp-6]

%ifdef PREFIX
global _powd_c
export _powd_c
_powd_c:
%else
	global powd_c
	powd_c:
%endif
    push ebp
    mov ebp, esp
    sub esp, 6
    push ebx

    fstcw ctrlWord
    or ctrlWord, 110000000000b
    fldcw ctrlWord

    fld b
    fld a
    fyl2x

    fist tmp

    fild tmp
    fsub
    f2xm1
    fld1
    fadd
    fild tmp
    fxch
    fscale

    mov ebx, result
    fst QWORD [ebx]

    pop ebx
    mov esp, ebp
    pop ebp
 ret
