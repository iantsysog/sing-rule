# Resources

### Structure

=== "Structure"

    ```json
    {
      "geoip": {},
      "geosite": {},
      "ipasn": {}
    }
    ```

### Resource Structure

```json
{
  ... // Source Fetch Fields
  ... // Source Convert Fields
}
```

### Fields

#### geoip

GEOIP resource.

If configured, all converted GEOIP rule items are replaced by the configured resource item during conversion.

#### geosite

GEOSITE resource.

If configured, all converted GEOSITE rule items are replaced by the configured resource item during conversion.

#### ipasn

IPASN resource.

If configured, all converted IPASN rule items are replaced by the configured resource item during conversion.

### Source Fetch Fields

See [Source Fetch Fields](/configuration/endpoint/file/#__tabbed_1_2).

The corresponding resource key is filled in the path or URL template.

| Resource | Key     | Description                        |
|----------|---------|------------------------------------|
| GEOIP    | `.code` | The GEOIP code                     |
| GEOSITE  | `.code` | The GEOSITE code                   |
| IPASN    | `.asn`  | The Autonomous System Number (ASN) |

### Source Convert Fields

See [Source Convert Fields](/configuration/convertor/#source-structure).
