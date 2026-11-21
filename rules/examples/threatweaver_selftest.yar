/*
  ThreatWeaver self-test rule (authored for this project, public domain).
  Matches a harmless marker string so the YARA tier can be tested end to end.
  Copy real rule sets into %LOCALAPPDATA%\ThreatWeaver\rules\yara\ yourself;
  ThreatWeaver bundles no third-party rules.
*/
rule ThreatWeaver_SelfTest_Marker
{
    meta:
        description = "Harmless test marker used by ThreatWeaver's test suite"
    strings:
        $m = "THREATWEAVER-YARA-SELFTEST-7f3c"
    condition:
        $m
}
