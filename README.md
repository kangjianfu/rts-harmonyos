# rts-harmonyos — 鸿蒙超低延迟拉流库（WHEP / 阿里云 RTS）

> **状态：开发中（WIP）**。目标：纯 HarmonyOS 实现的 WebRTC 拉流播放（亚秒级延迟，300~500ms），
> 与 [rtmpush-harmonyos](https://github.com/kangjianfu/rtmpush-harmonyos)（推流）、
> [rtmpull-harmonyos](https://github.com/kangjianfu/rtmpull-harmonyos)（FLV 拉流播放）组成鸿蒙直播全家桶。

## 服务端前提（重要）

超低延迟不是客户端单方面能做的，**服务端必须支持 RTC**：

- **SRS**：开启 RTC 支持（WHEP 端点 `/rtc/v1/whep/?app=..&stream=..`）
- **阿里云直播**：控制台开通 RTS（超低延时直播），按 RTS 文档替换信令端点

## 协议栈与进度

| 阶段 | 内容 | 状态 |
|------|------|------|
| 1 | STUN（RFC 5389：Binding、MESSAGE-INTEGRITY 短期凭证、USERNAME 校验） | ✅ 完成 |
| 1 | ICE-lite 受控侧（UDP 配对、USE-CANDIDATE、NAT 保活） | ✅ 完成 |
| 1 | SDP 解析/生成（recvonly offer：H.264 + opus） | ✅ 完成 |
| 1 | WHEP 信令（HTTP POST SDP offer → answer） | ✅ 完成 |
| 2 | DTLS 1.2 握手客户端（ArkTS cryptoFramework：ECDHE/AES-GCM/证书指纹校验） | 🚧 进行中 |
| 3 | SRTP 解密（AES-CM）+ RTP 解包（H.264 FU-A/STAP-A） | ⬜ 待做 |
| 3 | opus 音频解码接入；视频帧送 rtmpull 的 native 解码器直渲 | ⬜ 待做 |
| 4 | demo App + 真机验证（端到端延迟测量） | ⬜ 待做 |

## 设计约束

- 全程**纯 ArkTS + cryptoFramework**（DTLS/SRTP 自己实现），不引入 libwebrtc（体积与移植成本不可接受）
- 只做**拉流播放**（recvonly），推流仍走 RTMP（rtmpush）
- 解码渲染复用 [rtmpull-harmonyos](https://github.com/kangjianfu/rtmpull-harmonyos) 的 native 解码器（surface 零拷贝直渲）

## License

Apache-2.0（见 [LICENSE](LICENSE)、[NOTICE](NOTICE)）

---

由 [视创新云（北京）科技有限公司](https://www.widk.cn) 开源 · 体云动赛事平台（www.widk.cn）生产环境打磨
