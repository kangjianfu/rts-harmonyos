// Sdp.ets — SDP 极简解析/生成（WHEP/RTS 拉流信令用）
// 只处理拉流场景必需的字段：ice-ufrag/ice-pwd/fingerprint/setup/candidate/mid

export interface SdpInfo {
  iceUfrag: string;
  icePwd: string;
  fingerprint: string;    // 对端 DTLS 证书指纹（sha-256 hex，冒号分隔）
  setup: string;          // actpass/passive/active
  candidates: string[];   // candidate 行原文
  audioMid: string;
  videoMid: string;
}

/** 解析 SDP 文本 */
export function parseSdp(sdp: string): SdpInfo {
  const lines = sdp.split(/\r?\n/);
  const info: SdpInfo = {
    iceUfrag: '', icePwd: '', fingerprint: '', setup: '',
    candidates: [], audioMid: '', videoMid: ''
  };
  let currentMid = '';
  let currentMedia = '';
  for (const line of lines) {
    if (line.startsWith('a=ice-ufrag:')) {
      info.iceUfrag = line.slice(12).trim();
    } else if (line.startsWith('a=ice-pwd:')) {
      info.icePwd = line.slice(10).trim();
    } else if (line.startsWith('a=fingerprint:')) {
      // a=fingerprint:sha-256 AA:BB:...
      info.fingerprint = line.slice(14).trim();
    } else if (line.startsWith('a=setup:')) {
      info.setup = line.slice(8).trim();
    } else if (line.startsWith('a=candidate:')) {
      info.candidates.push(line.slice(2));
    } else if (line.startsWith('m=')) {
      currentMedia = line.slice(2, 6).trim();
    } else if (line.startsWith('a=mid:')) {
      currentMid = line.slice(6).trim();
      if (currentMedia.startsWith('audio')) {
        info.audioMid = currentMid;
      } else if (currentMedia.startsWith('video')) {
        info.videoMid = currentMid;
      }
    }
  }
  return info;
}

export interface CandidateAddr {
  host: string;
  port: number;
}

/** 从 candidate 行解析 udp host 地址（candidate:foundation comp proto priority ip port typ host ...） */
export function parseCandidate(line: string): CandidateAddr | null {
  const parts = line.split(/\s+/);
  if (parts.length < 6) {
    return null;
  }
  return { host: parts[4], port: parseInt(parts[5]) };
}

/** 生成拉流端 SDP offer（recvonly 音视频，H.264 + opus，ice-lite 对端） */
export function buildOffer(localUfrag: string, localPwd: string, dtlsFingerprint: string): string {
  const lines: string[] = [
    'v=0',
    'o=- 0 0 IN IP4 127.0.0.1',
    's=rtmpull-rts',
    't=0 0',
    'a=group:BUNDLE 0 1',
    'm=audio 9 UDP/TLS/RTP/SAVPF 111',
    'c=IN IP4 0.0.0.0',
    'a=mid:0',
    'a=recvonly',
    'a=rtcp-mux',
    'a=ice-ufrag:' + localUfrag,
    'a=ice-pwd:' + localPwd,
    'a=ice-options:trickle',
    'a=fingerprint:sha-256 ' + dtlsFingerprint,
    'a=setup:active',
    'a=rtpmap:111 opus/48000/2',
    'm=video 9 UDP/TLS/RTP/SAVPF 96',
    'c=IN IP4 0.0.0.0',
    'a=mid:1',
    'a=recvonly',
    'a=rtcp-mux',
    'a=rtpmap:96 H264/90000',
    'a=fmtp:96 packetization-mode=1;profile-level-id=42e01f',
  ];
  return lines.join('\r\n') + '\r\n';
}
