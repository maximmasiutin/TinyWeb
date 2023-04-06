@echo off
if exist TinyWeb.7z del TinyWeb.7z
if exist Tiny.exe del Tiny.exe
C:\FPC\3.2.2\bin\i386-win32\fpc.exe -OpCOREAVX2 -O4 -Pi386 -Twin32 -B -MObjFPC Tiny.dpr
7z a -mx9 TinyWeb Tiny.exe
