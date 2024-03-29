format PE CONSOLE          ;����������� ���� Windows EXE

include 'D:\FASM\INCLUDE\win32ax.inc'
include 'D:\FASM\INCLUDE\MACRO\proc32.inc'

; ������ ������
section '.data' data readable writeable
; �������� ����������
argc        dd ?
argv        dd ?
env         dd ?
; ��������
lenStr      dd ?
mbuf        dd ?
; ����
mStackDown  dd ?
mStackUp    dd ?
mCount      dd 10
; ������
errmsg      db "Error run time",0
errmem      db "Error memory",0

section '.code' code readable executable

entry start   ;����� ����� � ���������

;EAX 32 �����������

start:
  cinvoke malloc,8                     ; std::malloc(2*sizeof(char))
  mov [mStackDown],eax                 ; mStackDown = eax
  mov [mStackUp],eax                   ; mStackUp = eax

; argc = 1; argv = ["���� ������"]
 cinvoke __getmainargs,argc,argv,env,0 ; int main(int argc, char **argv)
 .if ([argc] = 2)
      jne .err ; throw err;
 .endif
 mov esi,[argv]   ; char **esi = argv;
; argc = 1; esi = ["���� ������"]

;�������� ������ ������ � ��������� ������ � ���������� ����������
  mov eax,[esi+4]  ; eax = esi + sizeof(char); // esi ���������, [esi] == *esi
  mov [mbuf],eax ; mbuf = eax // eax ����� �.�. ������ ���������� ���� � ����
  invoke strlen,dword[esi+4] ; eax = strlen(dword[esi+4]) // dword ��� unsigned int
  mov [lenStr],eax ; lenStr = eax

;��������� � ����'
  mov ebx,0 ; ebx = 0;
  mov esi,[mbuf] ; esi = mbuf // "���� ������"
  .mforin:
        .if ([lenStr] = ebx)
            je .mprint
        .endif

        ;eax = mPush(dword[esi])
        push dword[esi]
        call mPush
        pop eax
        ;
        .if (eax = 0)
             je .errfinish
        .endif
        inc esi ; esi++
        inc ebx ; ebx++
  jmp .mforin

; ����� ���������� � �������� �������
  .mprint:
   .if (ebx = 0)
      je .finish
   .endif
   call mPop ; edi = mPop()
   invoke printf,'%c',edi ; printf('%c',edi)
   dec ebx ; ebx--
   jmp .mprint

.errfinish:
 cinvoke puts,errmem
 jmp .finish

.finish:
 invoke ExitProcess,0

; ������ �����
.err:
 cinvoke puts,errmsg
 jmp .finish

; Push ������ ������� (���������� eax ��� ������������� ��������)
proc mPush, a:dword
  .if([mCount]=0)
        je .errMem
  .endif
  cinvoke malloc,8                      ; �������� ������ �� ����� ������
  mov edx,eax                           ; ������� ����� ������
  mov edi,[mStackUp]                    ; ��������� ����� ������� ������� ������
  mov [edx],edi                         ; ��������� ����� ������� ������� ������
  mov [mStackUp],edx                    ; ��������� ����� ������� ������
  add edx,4                             ; ������ �� ������ ����� ������
  mov edi,[a]                           ; ��������� ��������
  mov [edx],edi                         ; ���������� �������� � ������
  dec [mCount]                          ; ��������� ��������� �����
  push 1                                ; �� �������
  ret

  .errMem:                              ; ������ ����
  push 0                                ; � ������� ��
  ret
endp

; Pop ������ ������� (���������� eax ��� ������������� ��������)
proc mPop
  mov edx,[mStackUp]                    ; ��������� ����� ������, ������� ����� ���������
  mov edi,[edx]                         ; ��������� ����� ������ �������� �����
  mov [mStackUp],edi                    ; � ��� ��� ��� ����
  add edx,4                             ; ��� � �������, �� ����� �����������
  mov edi,[edx]                         ; ����������� ���
  inc [mCount]                          ; ���������� �����
  ret
endp

; �������� ������������ �������
section '.idata' import data readable writeable

library kernel,'kernel32.dll',\
msvcrt,'msvcrt.dll',\
user32,'user32.dll'

import kernel,\
ExitProcess,'ExitProcess',\
SetConsoleOutputCP,'SetConsoleOutputCP',\
SetConsoleCP,'SetConsoleCP'

import msvcrt,\
__getmainargs,'__getmainargs',\
printf,'printf',\
_getch,'_getch',\
puts,'puts',\
strlen,'strlen',\
malloc,'malloc'