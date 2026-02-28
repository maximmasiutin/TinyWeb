program test_val;

{$MODE OBJFPC}

uses
  xBase;

procedure Check(const S: AnsiString; ExpectedResult: Boolean; ExpectedValue: Integer);
var
  V: Integer;
  R: Boolean;
begin
  V := 0;
  R := _Val(S, V);
  if (R = ExpectedResult) and (V = ExpectedValue) then
    Writeln('PASS: "', S, '" -> ', R, ', ', V)
  else
    Writeln('FAIL: "', S, '" -> ', R, ', ', V, ' (Expected: ', ExpectedResult, ', ', ExpectedValue, ')');
end;

begin
  Writeln('Testing _Val with overflow protection:');
  Check('10', True, 10);
  Check('2147483647', True, 2147483647);
  Check('2147483648', False, 0); // Overflow
  Check('4294967306', False, 0); // Overflow (4GB + 10)
  Check('0', True, 0);
  Check('', False, 0);
  Check('abc', False, 0);
end.
