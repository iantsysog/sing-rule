# AdGuard

AdGuard DNS Filter.

A special rule-set format supported by sing-box, covering most syntax supported by AdGuard Home.

Because it includes rule types that cannot be represented in most other formats,
it can only be converted to and from `binary`.

### Source Structure

```json
{
  "source_type": "adguard",
  "accept_extended_rules": false
}
```

### Target Structure

```json
{
  "target_type": "binary"
}
```

### Source Fields

#### accept_extended_rules

If not enabled, only rule items that can be expressed as `domain`, `domain_suffix`, or `domain_regex` are parsed; other items are ignored.

If enabled, most rules supported by AdGuard DNS Filter are parsed, but conversion is limited to sing-box rule-set binary.

For compatibility details, see [AdGuard DNS Filter](https://sing-box.sagernet.org/configuration/rule-set/adguard/).
