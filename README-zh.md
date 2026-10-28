<p align="center"><a href="README.md">English</a> · <b>简体中文</b></p>

# HelloCar

面向 Linux 的无线 HiCar 接收端，为开发者在自己的应用中集成手机投屏提供基础能力。

HelloCar 负责发现、配对、认证和投屏会话，通过本地 Unix socket 输出 H.264 视频、PCM 音频，并将触摸和按键输入传回手机。显示、音频播放和用户界面由接入方实现。

接收核心使用 Rust，HiChain/HUKS 认证适配库使用 C。Python 用于身份配置、示例和协议回归测试。

## 项目定位

HelloCar 提供**无线 HiCar 连接的接收侧实现**，可作为独立进程，接入播放器、嵌入式界面或其他投屏应用。

```text
HiCar 手机  <── 蓝牙 / Wi-Fi ──>  HelloCar  <── Unix socket ──>  你的应用
                                  接收端                       视频 · 音频 · 输入
```

| HelloCar 负责 | 接入方负责 |
| --- | --- |
| 蓝牙发现、配对和连接建立 | 设备选择与配对界面 |
| 认证和持久化设备身份 | 向用户显示配对 PIN |
| 临时 Wi-Fi 热点与会话传输 | 系统网络策略和服务管理 |
| 视频接收与音频解码 | 视频渲染、音频播放和延迟控制 |
| 触摸/按键回传及会话事件 | 输入设备、焦点、菜单和输出适配 |

本仓库专注于接收端及其集成接口。桌面播放器、浏览器接收端、车机输出、系统镜像和多协议设备管理器属于接入方的范围。

## 功能与状态

- 无线发现与配对，持久化六位固定 PIN。
- 新设备认证与已配对设备认证。
- DMSDP 会话控制与 HiSight 媒体传输。
- H.264 视频透传；通过 FFmpeg 将 AAC 音频解码为双声道 PCM。
- 触摸、拖动、抬起和按键输入回传。
- 麦克风上行及通话音频会话，由接入方提供麦克风 PCM。
- 按音源独立解码，并通过有界 PCM 混音输出。
- 向接入方提供会话状态、音频启停和视频恢复通知。
- Linux 命令行接收端，以及包含协议模块的 Rust crate。

**兼容目标：鸿蒙 4.2。** 鸿蒙 5、6 暂不在支持范围内。项目处于实验阶段，稳定版发布前协议细节和 Rust API 可能调整。麦克风与通话音频通路属于实验功能，需要设备验证；采集、播放和通话界面由接入方提供。

## 运行要求

- Linux，安装 BlueZ、系统 D-Bus 和 NetworkManager。
- 蓝牙支持 BR/EDR 和 BLE 广播；Wi-Fi 接口支持 5 GHz AP 模式。
- 支持 AAC 解码与编码的 FFmpeg；身份配置和录制示例需要 Python 3。
- 管理所选蓝牙适配器和 Wi-Fi 接口的权限。以下示例使用 root。

二进制包面向 **x86_64** 和 **ARMv7 hard-float**，以 Debian 12 / glibc 2.36 为运行基线。随包运行库及其许可证记录在包内清单中。

当前无线配置使用 **149 信道 / 5745 MHz** 和 **192.168.49.0/24** 子网。使用前确认所在地区允许该信道，且网卡支持。HelloCar 会临时管理所选 Wi-Fi 接口，开发时请保留独立的管理连接。

## 快速开始

使用仓库 **Linux receiver build and validation** 工作流生成的 Linux 包。解压与设备架构匹配的包，在包根目录执行以下命令。源码目录中的 `bin/hellocar` 启动器依赖安装包的 `libexec/`、`lib/` 目录布局。

Debian 系统可安装以下服务和工具：

```sh
sudo apt-get install bluez network-manager libdbus-1-3 iproute2 iw ffmpeg python3
sha256sum -c SHA256SUMS
sudo install -d -m 700 /var/lib/hellocar /run/hellocar
sudo python3 tools/identity.py init
sudo python3 tools/identity.py show-pin
```

`init` 首次创建私有身份和 PIN，重复执行会保留已有身份。升级时保留身份文件和认证存储目录。

在一个终端启动录制示例，作为本地媒体消费者：

```sh
sudo python3 examples/record_media.py \
  --output /var/tmp/hellocar-capture --duration 120
```

在另一个终端启动接收端，将 `wlan0` 替换为用于热点的无线接口：

```sh
sudo bin/hellocar run --network-interface wlan0 --pair 120
```

打开手机蓝牙和 Wi-Fi，在 HiCar 发现设备后选择 **HelloCar**，输入 `show-pin` 显示的 PIN。示例保存 `video.h264` 和 `audio.s16le`，默认最多录制 120 秒或 64 MiB；它用于录制媒体，显示和播放由接入方实现。

已配对手机可按蓝牙地址连接：

```sh
sudo bin/hellocar run --network-interface wlan0 --peer AA:BB:CC:DD:EE:FF
```

身份管理、权限和命令行选项见[使用与排错](docs/usage.md)。

## 如何集成

建议将 HelloCar 作为**独立进程**运行，按照[本地媒体协议](docs/media-protocol.md)实现消费者：

1. 启动接收端前，先监听私有 Unix stream socket。
2. 接收配置、会话事件、H.264 访问单元和 PCM 音频。
3. 通过同一 socket 回传触摸和按键。
4. 在渲染和播放端处理断开、音频代次及关键帧恢复。

默认 socket 是 `/run/hellocar/media.sock`，可通过 `--live-socket` 修改。HelloCar 是主动连接的**客户端**。[录制示例](examples/record_media.py)展示了消费者及有界媒体处理。

Rust crate 通过 `hellocar::hicar` 暴露协议模块，供协议开发和进一步集成。这些模块属于实现级接口，尚未形成稳定的高层播放器 API；集成时仍需原生认证库和 Linux 系统服务。

## 目录结构

| 路径 | 内容 |
| --- | --- |
| [`src/`](src) | Rust 库和命令行入口 |
| [`src/hicar/`](src/hicar) | 发现、认证、会话控制、媒体与输入 |
| [`native/`](native) | C 认证适配层及固定版本的上游源码定义 |
| [`examples/`](examples) | 本地媒体录制器、身份配置及示例测试 |
| [`tests/reference/`](tests/reference) | 用于合成测试的 Python 协议参考实现 |
| [`tools/`](tools) | 身份配置、回归测试和打包工具 |
| [`docs/`](docs) | 运行说明和媒体消费者协议 |
| [`.github/workflows/`](.github/workflows) | Linux 构建、回归测试及包校验 |

## 开发

Rust 版本由 `rust-toolchain.toml` 固定，Rust 依赖锁定在 `Cargo.lock`，原生源码版本锁定在 `native/sources.json`。

GitHub Actions 构建两个架构，运行主机集成测试和 ARM QEMU 协议/认证测试，检查包结构及 ELF ABI，并上传带 SHA256 清单的产物。构建入口为 `tools/build.sh`。

身份配置和示例测试可独立运行：

```sh
python3 -m unittest discover -s examples -p 'test_*.py'
```

修改和测试约定见 [CONTRIBUTING.md](CONTRIBUTING.md)，身份资料和问题报告见 [SECURITY.md](SECURITY.md)。

## 许可证

HelloCar 项目代码使用 [MIT 许可证](LICENSE)。原生依赖和随包运行库保留各自许可证，详见 [NOTICE](NOTICE) 和包内许可证目录。

HiCar、Huawei 和 HarmonyOS 是其各自权利人的商标。HelloCar 是独立的互操作项目。
