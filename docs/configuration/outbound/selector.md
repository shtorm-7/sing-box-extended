### Structure

```json
{
  "type": "selector",
  "tag": "select",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "providers": [
    "provider-a",
    "provider-b",
  ],
  "exclude": "",
  "include": "",
  "default": "proxy-c",
  "use_all_providers": false,
  "interrupt_exist_connections": false
}
```

!!! quote ""

    The selector can only be controlled through the [Clash API](/configuration/experimental#clash-api-fields) currently.

### Fields

#### outbounds

List of outbound tags to select.

#### providers

List of [Provider](/configuration/provider) tags to select.

#### use_all_providers

Use all [Provider](/configuration/provider) to fill `outbounds`.

#### exclude

Exclude regular expression to filter `providers` nodes. The priority of the exclude expression is higher than the include expression.

#### include

Include regular expression to filter `providers` nodes.

#### default

The default outbound tag. The first outbound will be used if empty.

#### use_all_providers

Whether to use all providers for testing. `false` will be used if empty.

#### interrupt_exist_connections

Interrupt existing connections when the selected outbound has changed.

Only inbound connections are affected by this setting, internal connections will always be interrupted.
