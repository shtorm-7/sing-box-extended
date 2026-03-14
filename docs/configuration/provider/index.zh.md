# 订阅

### 结构

订阅源列表。

=== "本地文件"

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

=== "远程文件"

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

### 字段

#### type

==必填==

订阅源的类型。`local` 或 `remote`。

#### tag

==必填==

订阅源的标签。

来自 `provider` 的节点 `node_name`，导入后的标签为 `provider/node_name`。

### 本地或远程字段

#### health_check

健康检查配置。

##### health_check.enabled

是否启用健康检查。

##### health_check.url

健康检查的 URL。

##### health_check.interval

健康检查的时间间隔。最小为 `1m`，默认为 `10m`。

##### health_check.timeout

健康检查的超时时间。默认为 `3s`。

### 本地字段

#### path

==必填==

!!! note ""

    自 sing-box 1.10.0 起， 文件更改将自动重新加载。

本地文件路径。

### 远程字段

#### url

==必填==

订阅源的 URL。

#### exclude

排除节点的正则表达式。

#### include

包含节点的正则表达式。

#### user_agent

用于下载订阅内容的 User-Agent。

#### download_detour

用于下载订阅内容的出站的标签。

如果为空，将使用默认出站。

#### update_interval

更新订阅的时间间隔。最小为 `1m`，默认为 `24h`。