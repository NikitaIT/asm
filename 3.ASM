format PE CONSOLE          ;исполняемый файл Windows EXE

include 'D:\FASM\INCLUDE\win32ax.inc'
include 'D:\FASM\INCLUDE\MACRO\proc32.inc'

; Секция данных
section '.data' data readable writeable
; загрузка параметров
argc        dd ?
argv        dd ?
env         dd ?
; параметр
lenStr      dd ?
mbuf        dd ?
; стек
mStackDown  dd ?
mStackUp    dd ?
mCount      dd 10
; ошибки
errmsg      db "Error run time",0
errmem      db "Error memory",0

section '.code' code readable executable

entry start   ;Точка входа в программу

;EAX 32 Аккумулятор

start:
  cinvoke malloc,8                     ; std::malloc(2*sizeof(char))
  mov [mStackDown],eax                 ; mStackDown = eax
  mov [mStackUp],eax                   ; mStackUp = eax

; argc = 1; argv = ["наша строка"]
 cinvoke __getmainargs,argc,argv,env,0 ; int main(int argc, char **argv)
 .if ([argc] = 2)
      jne .err ; throw err;
 .endif
 mov esi,[argv]   ; char **esi = argv;
; argc = 1; esi = ["наша строка"]

;Нахходим длинну строки и выгружаем строку в нормальную переменную
  mov eax,[esi+4]  ; eax = esi + sizeof(char); // esi указатель, [esi] == *esi
  mov [mbuf],eax ; mbuf = eax // eax нужен т.к. нельзя записывать дату в дату
  invoke strlen,dword[esi+4] ; eax = strlen(dword[esi+4]) // dword это unsigned int
  mov [lenStr],eax ; lenStr = eax

;Загружаем в стек'
  mov ebx,0 ; ebx = 0;
  mov esi,[mbuf] ; esi = mbuf // "наша строка"
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

; Вывод результата в обратном порядке
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

; Ошибка ввода
.err:
 cinvoke puts,errmsg
 jmp .finish

; Push нашего подобия (используем eax для возвращаемого значения)
proc mPush, a:dword
  .if([mCount]=0)
        je .errMem
  .endif
  cinvoke malloc,8                      ; Выделили память на новую ячейку
  mov edx,eax                           ; Считали адрес памяти
  mov edi,[mStackUp]                    ; Прочитали адрес прошлой верхней ячейки
  mov [edx],edi                         ; Сохраняем адрес прошлой верхней ячейки
  mov [mStackUp],edx                    ; Сохраняем новый верхнюю ячейку
  add edx,4                             ; Скачем на вторую часть ячейки
  mov edi,[a]                           ; Загружаем значение
  mov [edx],edi                         ; Записываем значение в ячейку
  dec [mCount]                          ; Уменьшаем доступное место
  push 1                                ; Всё отлично
  ret

  .errMem:                              ; Памяти хана
  push 0                                ; И поэтому всё
  ret
endp

; Pop нашего подобия (используем eax для возвращаемого значения)
proc mPop
  mov edx,[mStackUp]                    ; Сохранили адрес ячейки, которую будет разрушать
  mov edi,[edx]                         ; Сохранили адрес ячейки будущего верха
  mov [mStackUp],edi                    ; И вот она уже верх
  add edx,4                             ; Идём к символу, не видим препятствий
  mov edi,[edx]                         ; Вытаскиваем его
  inc [mCount]                          ; Освободили место
  ret
endp

; Точечные подтягивания функций
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