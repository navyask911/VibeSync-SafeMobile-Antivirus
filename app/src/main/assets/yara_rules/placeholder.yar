rule SafeMobile_YaraX_Integration_Placeholder
{
    meta:
        classification = "informational"
        severity = "low"
        description = "SafeMobile YARA-X integration placeholder; not a malware signature."
        malware_name = "SafeMobile integration placeholder"
    strings:
        $placeholder = "SAFEMOBILE_YARAX_PLACEHOLDER_MATCH_ONLY" ascii
    condition:
        $placeholder
}
