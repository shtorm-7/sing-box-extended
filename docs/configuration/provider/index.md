# Provider

### Structure

List of subscription providers.

=== "Local File"

    ```json
    {
      "providers": [
        {
          "type": "local",
          "tag": "provider",
          "path": "provider.txt",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
          }
        }
      ]
    }
    ```

=== "Remote File"

    ```json
    {
      "providers": [
        {
          "type": "remote",
          "tag": "provider",
          "health_check": {
            "enabled": false,
            "url": "",
            "interval": "",
            "timeout": "",
          },
          "url": "",
          "exclude": "",
          "include": "",
          "user_agent": "",
          "download_detour": "",
          "update_interval": ""
        }
      ]
    }
    ```

### Fields

#### type

==Required==

Type of the provider. `local` or `remote`.

#### tag

==Required==

Tag of the provider.

The node `node_name` from `provider` will be tagged as `provider/node_name`.

### Local or Remote Fields

#### health_check

Health check configuration.

##### health_check.enabled

Health check enabled.

##### health_check.url

Health check URL.

##### health_check.interval

Health check interval. The minimum value is `1m`, the default value is `10m`.

##### health_check.timeout

Health check timeout. the default value is `3s`.

### Local Fields

#### path

==Required==

!!! note ""

    Will be automatically reloaded if file modified since sing-box 1.10.0.

Local file path.

### Remote Fields

#### url

==Required==

URL to the provider.

#### exclude

Exclude regular expression to filter nodes.

#### include

Include regular expression to filter nodes.

#### user_agent

User agent used to download the provider.

#### download_detour

The tag of the outbound used to download from the provider.

Default outbound will be used if empty.

#### update_interval

Update interval. The minimum value is `1m`, the default value is `24h`.
