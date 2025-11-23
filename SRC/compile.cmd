@echo off
REM PP - path to Free Pascal compiler (standard FPC Makefile variable)
REM If not set, uses fpc.exe from PATH

if exist TinyWeb.7z del TinyWeb.7z
if exist Tiny.exe del Tiny.exe

if defined PP (
    "%PP%" -OpCOREAVX2 -O4 -Pi386 -Twin32 -B -MObjFPC Tiny.dpr
) else (
    fpc.exe -OpCOREAVX2 -O4 -Pi386 -Twin32 -B -MObjFPC Tiny.dpr
)

if exist "%ProgramFiles%\7-Zip\7z.exe" (
    "%ProgramFiles%\7-Zip\7z.exe" a -mx9 TinyWeb Tiny.exe
) else (
    7z.exe a -mx9 TinyWeb Tiny.exe
)
