# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import errno
import os
import pty
import select
import shutil
import socket
import subprocess
import termios
import time
from threading import Event, Lock, Thread
from typing import Callable, Optional, Set, Tuple

from cirque.capabilities.pcapcapability import (
    OT_SIM_DEFAULT_PORT_BASE,
    PcapCapability,
    ThreadRadioSniffer,
    ot_sim_radio_port,
)
from cirque.common.cirquelog import CirqueLog
from cirque.common.taskrunner import TaskRunner
from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

_HDLC_FLAG = 0x7E
# Per-direction output backlog at which the Spinel proxy stops reading the
# source until the destination drains.
_MAX_PENDING_BYTES = 64 * 1024
_HDLC_ESCAPE = 0x7D
_HDLC_INIT_FCS = 0xFFFF
_HDLC_GOOD_FCS = 0xF0B8
_HDLC_ESCAPE_BYTES = frozenset((0x11, 0x13, 0x7D, 0x7E, 0xF8))

_SPINEL_CMD_NOOP = 0x00
_SPINEL_CMD_PROP_VALUE_GET = 0x02
_SPINEL_CMD_PROP_VALUE_SET = 0x03
_SPINEL_CMD_PROP_VALUE_IS = 0x06
_SPINEL_PROP_LAST_STATUS = 0x00
_SPINEL_PROP_PHY_RSSI = 0x26
_SPINEL_PROP_STREAM_RAW = 0x71
_SPINEL_STATUS_OK = 0x00
_SPINEL_STATUS_NO_ACK = 0x11

_FCS_TABLE = (
    0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
    0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
    0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
    0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
    0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
    0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
    0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
    0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
    0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
    0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
    0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
    0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
    0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
    0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
    0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
    0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
    0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
    0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
    0x9489, 0x8500, 0xb79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
    0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
    0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
    0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
    0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
    0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
    0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
    0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
    0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
    0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
    0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
    0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
    0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
    0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78,
)


def hdlc_compute_fcs(data: bytes) -> int:
  """Computes the running RFC 1662 / OpenThread HDLC-lite 16-bit FCS."""
  fcs = _HDLC_INIT_FCS
  for b in data:
    fcs = (fcs >> 8) ^ _FCS_TABLE[(fcs ^ b) & 0xFF]
  return fcs


def hdlc_encode_frame(body: bytes) -> bytes:
  """Encodes an unescaped Spinel frame body with 16-bit FCS and 0x7E flags."""
  fcs = hdlc_compute_fcs(body) ^ 0xFFFF
  payload_with_fcs = body + bytes((fcs & 0xFF, (fcs >> 8) & 0xFF))
  out = bytearray((_HDLC_FLAG,))
  for b in payload_with_fcs:
    if b in _HDLC_ESCAPE_BYTES:
      out.append(_HDLC_ESCAPE)
      out.append(b ^ 0x20)
    else:
      out.append(b)
  out.append(_HDLC_FLAG)
  return bytes(out)


def hdlc_decode_frame(raw_between_flags: bytes) -> Optional[bytes]:
  """Unescapes an HDLC segment between 0x7E flags and verifies 16-bit FCS."""
  if not raw_between_flags:
    return None
  unescaped = bytearray()
  escaped = False
  for b in raw_between_flags:
    if escaped:
      unescaped.append(b ^ 0x20)
      escaped = False
    elif b == _HDLC_ESCAPE:
      escaped = True
    else:
      unescaped.append(b)
  if escaped or len(unescaped) < 2:
    return None
  if hdlc_compute_fcs(unescaped) != _HDLC_GOOD_FCS:
    return None
  return bytes(unescaped[:-2])


def _configure_raw_tty(fd: int) -> None:
  """Configures a PTY descriptor for raw Spinel HDLC byte transport."""
  try:
    if not os.isatty(fd):
      return
    attrs = termios.tcgetattr(fd)
    attrs[0] = 0  # c_iflag = 0
    attrs[1] = 0  # c_oflag = 0
    attrs[2] = (
        attrs[2] & ~(termios.CSIZE | termios.PARENB | termios.HUPCL)
    ) | termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0  # c_lflag = 0
    attrs[6][termios.VMIN] = 1
    attrs[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
  except (OSError, termios.error):
    pass

def _parse_802154_data_addrs(psdu: bytes) -> Tuple[Optional[str], Optional[str]]:
  if len(psdu) < 3:
    return None, None
  fcf0, fcf1 = psdu[0], psdu[1]
  if (fcf0 & 0x07) != 1:  # Not Data
    return None, None
  pan_id_comp = (fcf0 >> 6) & 0x01
  dest_mode = (fcf1 >> 2) & 0x03
  src_mode = (fcf1 >> 6) & 0x03
  offset = 3
  dest_addr = None
  if dest_mode > 0:
    offset += 2  # Dest PAN
    if dest_mode == 2 and len(psdu) >= offset + 2:
      dest_addr = psdu[offset : offset + 2]
      offset += 2
    elif dest_mode == 3 and len(psdu) >= offset + 8:
      dest_addr = psdu[offset : offset + 8]
      offset += 8
  src_addr = None
  if src_mode > 0:
    if pan_id_comp == 0 and len(psdu) >= offset + 2:
      offset += 2  # Src PAN
    if src_mode == 2 and len(psdu) >= offset + 2:
      src_addr = psdu[offset : offset + 2]
    elif src_mode == 3 and len(psdu) >= offset + 8:
      src_addr = psdu[offset : offset + 8]
  def fmt(b):
    return b[::-1].hex().lower() if b else None
  return fmt(src_addr), fmt(dest_addr)
class SpinelHdlcRfProxy:
  """Pure-Cirque Spinel HDLC proxy between Host (otbr-agent) and RCP (ot-rcp).

  Intercepts Spinel radio frames on the Cirque host side without requiring any
  modifications to OpenThread's C/C++ codebase:
    1. Outbound Host -> RCP `SPINEL_PROP_STREAM_RAW` (`cmd=3, prop=0x71`):
       Evaluates `RfChannelSimulator` link physics; when a unicast data frame
       (`psdu_len >= 60`, `is_retx == 0`) is stochastically dropped, records
       its Spinel transaction ID (`tid`) and rewrites the RCP's
       `SPINEL_PROP_LAST_STATUS` response into `SPINEL_STATUS_NO_ACK (0x11)`
       while preserving `headerUpdated = 1` and the 5-byte
       `(keyIndex, frameCounter)` MAC security trailer so `otbr-agent` records
       a genuine 802.15.4 MAC `NoAck` + retry without wedging `sTxWait`.
    2. Inbound RCP -> Host `SPINEL_PROP_STREAM_RAW` (`cmd=6, prop=0x71`):
       Rewrites `rssi`, `noise_floor`, and `lqi` in `PackRadioFrame` with
       simulated path-loss, noise/interference, and SINR.
    3. Inbound RCP -> Host `SPINEL_PROP_LAST_STATUS` (`cmd=6, prop=0x00`):
       Rewrites `rssi`, `noise_floor`, and `lqi` in the embedded 802.15.4 ACK
       `PackRadioFrame` so OpenThread neighbor tables reflect exact RSSI/LQI.
    4. Inbound RCP -> Host `SPINEL_PROP_PHY_RSSI` (`cmd=6, prop=0x26`):
       Rewrites the CCA ambient RSSI query (`ot-ctl rssi`) with the simulated
       noise + co-channel interference floor.
  """

  def __init__(
      self,
      node_id: int,
      simulator: Optional[RfChannelSimulator] = None,
  ):
    self.node_id = int(node_id)
    self._sim = simulator
    self._lock = Lock()
    self._pending_no_ack_tids: Set[int] = set()
    self._host_rx_buf = bytearray()
    self._rcp_rx_buf = bytearray()
    self._stop_event = Event()
    self._thread: Optional[Thread] = None
    self._logger = CirqueLog.get_cirque_logger(self.__class__.__name__)
    self._host_tx_frames = 0
    self._rcp_rx_frames = 0
    self._last_rcp_mac_seq = -1
    self._last_host_tid = -1

  def _get_sim(self) -> RfChannelSimulator:
    if self._sim is not None:
      return self._sim
    return RfChannelSimulator.get_shared()

  def transform_host_to_rcp(self, body: bytes) -> Optional[bytes]:
    """Transforms a decoded Spinel frame body flowing from Host to RCP."""
    if len(body) >= 2 and body[1] == 0x01:
      self._logger.info(
          'node %s: Host->RCP RESET (prev tx_cnt=%d rx_cnt=%d last_rx_seq=%d)',
          self.node_id,
          self._host_tx_frames,
          self._rcp_rx_frames,
          self._last_rcp_mac_seq,
      )
      self._host_tx_frames = 0
      self._rcp_rx_frames = 0
      self._last_rcp_mac_seq = -1
      with self._lock:
        self._pending_no_ack_tids.clear()
    if (
        len(body) >= 8
        and body[1] == _SPINEL_CMD_PROP_VALUE_SET
        and body[2] == _SPINEL_PROP_STREAM_RAW
    ):
      self._host_tx_frames += 1
      self._last_host_tid = body[0] & 0x0F
      psdu_len = body[3] | (body[4] << 8)
      mac_seq = body[7]
      self._logger.info(
          'node %s: Host->RCP STREAM_RAW tid=%d seq=%d len=%d (tx_cnt=%d'
          ' rx_cnt=%d last_rx_seq=%d)',
          self.node_id,
          self._last_host_tid,
          mac_seq,
          psdu_len,
          self._host_tx_frames,
          self._rcp_rx_frames,
          self._last_rcp_mac_seq,
      )
    sim = self._get_sim()
    has_fault = bool(getattr(sim.config, 'fault_rule', None) and sim.config.fault_rule.rule)
    if not sim.config.enabled and not has_fault:
      return body
    if (
        len(body) >= 5
        and body[1] == _SPINEL_CMD_PROP_VALUE_SET
        and body[2] == _SPINEL_PROP_STREAM_RAW
    ):
      psdu_len = body[3] | (body[4] << 8)
      meta_offset = 5 + psdu_len
      if 3 <= psdu_len <= 127 and len(body) >= meta_offset + 6:
        fcf_lo = body[5]
        frame_type = fcf_lo & 0x07
        
        fault_rule = getattr(sim.config, 'fault_rule', None)
        if frame_type == 1:
            psdu_extract = body[5:5+psdu_len]
            src, dst = _parse_802154_data_addrs(psdu_extract)
            self._logger.info('node %s: Host->RCP DATA (len=%d, src=%s, dst=%s)', self.node_id, psdu_len, src, dst)
        if fault_rule and fault_rule.rule == 'sigma2_blackhole':
          if frame_type == 1:
            psdu_extract = body[5:5+psdu_len]
            _, dst = _parse_802154_data_addrs(psdu_extract)
            allowed_dsts = {
                s.lower().replace('0x', '')
                for s in (fault_rule.src_ext, getattr(fault_rule, 'src_short', ''))
                if s
            }
            if dst and (dst.lower().replace('0x', '') in allowed_dsts):
              self._logger.info('node %s: Host->RCP burst detected to dst=%s, arming trigger_time', self.node_id, dst)
              if fault_rule.trigger_time == 0.0:
                fault_rule.trigger_time = time.time()
            
        security_enabled = (fcf_lo & 0x08) != 0
        ack_requested = (fcf_lo & 0x20) != 0
        channel = body[meta_offset]
        is_retx = body[meta_offset + 5]
        sample = sim.evaluate_packet(
            'thread',
            src_id=f'thread_node_{self.node_id}',
            dst_id='thread_air',
            channel=channel if 11 <= channel <= 26 else None,
            frame_len_bytes=psdu_len,
            record_telemetry=True,
        )
        should_drop_ack = (
            sample.dropped
            and frame_type == 1
            and ack_requested
            and security_enabled
            and psdu_len >= 60
            and is_retx == 0
            and (body[0] & 0x0F) != 0
        )
        if should_drop_ack:
          with self._lock:
            self._pending_no_ack_tids.add(body[0] & 0x0F)
    return body

  def _rewrite_packed_radio_frame(
      self, mutable: bytearray, pack_offset: int
  ) -> bool:
    """Rewrites rssi, noise_floor, and lqi inside a Spinel PackRadioFrame."""
    if len(mutable) < pack_offset + 2:
      return False
    psdu_len = mutable[pack_offset] | (mutable[pack_offset + 1] << 8)
    if not (3 <= psdu_len <= 127):
      return False
    if len(mutable) < pack_offset + 2 + psdu_len + 10:
      return False
    phy_struct_len = (
        mutable[pack_offset + 6 + psdu_len]
        | (mutable[pack_offset + 7 + psdu_len] << 8)
    )
    if phy_struct_len < 2:
      return False
    rssi_idx = pack_offset + 2 + psdu_len
    noise_idx = pack_offset + 3 + psdu_len
    channel_idx = pack_offset + 8 + psdu_len
    lqi_idx = pack_offset + 9 + psdu_len
    channel = mutable[channel_idx]

    sim = self._get_sim()
    sample = sim.evaluate_packet(
        'thread',
        src_id='thread_air',
        dst_id=f'thread_node_{self.node_id}',
        channel=channel if 11 <= channel <= 26 else None,
        frame_len_bytes=psdu_len,
        record_telemetry=True,
    )
    eff_params = sim.compute_thread_effective_params()
    eff_noise = int(
        round(eff_params.get('effective_noise_dbm', sample.noise_floor_dbm))
    )
    rssi_s8 = max(-127, min(20, int(sample.rssi_dbm)))
    noise_s8 = max(-127, min(-40, eff_noise))
    lqi_u8 = max(1, min(255, int(sample.lqi)))

    mutable[rssi_idx] = rssi_s8 & 0xFF
    mutable[noise_idx] = noise_s8 & 0xFF
    mutable[lqi_idx] = lqi_u8 & 0xFF
    return True

  def transform_rcp_to_host(self, body: bytes) -> Optional[bytes]:
    """Transforms a decoded Spinel frame body flowing from RCP to Host."""
    if (
        len(body) >= 8
        and body[1] == _SPINEL_CMD_PROP_VALUE_IS
        and body[2] == _SPINEL_PROP_STREAM_RAW
    ):
      self._rcp_rx_frames += 1
      self._last_rcp_mac_seq = body[7]
      if self._rcp_rx_frames % 10 == 0 or self._rcp_rx_frames >= 100:
        self._logger.info(
            'node %s: RCP->Host STREAM_RAW rx_cnt=%d seq=%d',
            self.node_id,
            self._rcp_rx_frames,
            self._last_rcp_mac_seq,
        )
    if (
        len(body) >= 4
        and body[1] == _SPINEL_CMD_PROP_VALUE_IS
        and body[2] == _SPINEL_PROP_LAST_STATUS
    ):
      tid = body[0] & 0x0F
      self._logger.info(
          'node %s: RCP->Host LAST_STATUS tid=%d status=%d len=%d',
          self.node_id,
          tid,
          body[3],
          len(body),
      )
      if tid != 0:
        with self._lock:
          if tid in self._pending_no_ack_tids:
            self._pending_no_ack_tids.discard(tid)
            if (
                len(body) >= 11
                and body[3] == _SPINEL_STATUS_OK
                and body[5] == 0x01
            ):
              return (
                  bytes((
                      body[0],
                      _SPINEL_CMD_PROP_VALUE_IS,
                      _SPINEL_PROP_LAST_STATUS,
                      _SPINEL_STATUS_NO_ACK,
                      0x00,
                      0x01,
                  ))
                  + body[-5:]
              )
            return bytes((
                body[0],
                _SPINEL_CMD_PROP_VALUE_IS,
                _SPINEL_PROP_LAST_STATUS,
                _SPINEL_STATUS_NO_ACK,
                0x00,
                0x00,
            ))

    sim = self._get_sim()
    has_fault = bool(getattr(sim.config, 'fault_rule', None) and sim.config.fault_rule.rule)
    if not sim.config.enabled and not has_fault:
      return body

    # Case 1: Inbound RX frame (SPINEL_PROP_STREAM_RAW = 0x71)
    if (
        len(body) >= 5
        and body[1] == _SPINEL_CMD_PROP_VALUE_IS
        and body[2] == _SPINEL_PROP_STREAM_RAW
    ):
      psdu_len = body[3] | (body[4] << 8)
      if 3 <= psdu_len <= 127 and len(body) >= 5 + psdu_len:
        psdu = body[5:5+psdu_len]
        frame_type = psdu[0] & 0x07
        fault_rule = getattr(sim.config, 'fault_rule', None)
        if frame_type == 1:
            src, dst = _parse_802154_data_addrs(psdu)
            self._logger.info('node %s: RCP->Host DATA (len=%d, src=%s, dst=%s)', self.node_id, psdu_len, src, dst)
        if fault_rule and fault_rule.rule == 'sigma2_blackhole':
          if time.time() - fault_rule.trigger_time < fault_rule.window_s:
            allowed_srcs = {
                s.lower().replace('0x', '')
                for s in (fault_rule.src_ext, getattr(fault_rule, 'src_short', ''))
                if s
            }
            if frame_type == 1:
              src_clean = (src or '').lower().replace('0x', '')
              src_match = (not allowed_srcs) or (src_clean in allowed_srcs)
              self._logger.info('node %s: CHECKING Sigma2 frame (len=%d, src=%s, src_match=%s, thresh=%s)', self.node_id, psdu_len, src, src_match, fault_rule.psdu_threshold)
              if src_clean and src_match and psdu_len >= fault_rule.psdu_threshold:
                fault_rule.dropped_count += 1
                self._logger.info('node %s: BLACKHOLED Sigma2 frame (len=%d, src=%s)', self.node_id, psdu_len, src)
                return None

      mutable = bytearray(body)
      if self._rewrite_packed_radio_frame(mutable, pack_offset=3):
        return bytes(mutable)
      return body

    # Case 2: Inbound TX-Done status with ACK PackRadioFrame at offset 6
    if (
        len(body) >= 8
        and body[1] == _SPINEL_CMD_PROP_VALUE_IS
        and body[2] == _SPINEL_PROP_LAST_STATUS
        and body[3] == _SPINEL_STATUS_OK
    ):
      mutable = bytearray(body)
      if self._rewrite_packed_radio_frame(mutable, pack_offset=6):
        return bytes(mutable)
      return body

    # Case 3: Inbound CCA / energy-detect RSSI query (SPINEL_PROP_PHY_RSSI)
    if (
        len(body) == 4
        and body[1] == _SPINEL_CMD_PROP_VALUE_IS
        and body[2] == _SPINEL_PROP_PHY_RSSI
    ):
      eff_params = sim.compute_thread_effective_params()
      cca_rssi = max(
          -127,
          min(-20, int(round(eff_params.get('effective_noise_dbm', -95.0)))),
      )
      mutable = bytearray(body)
      mutable[3] = cca_rssi & 0xFF
      return bytes(mutable)

    return body

  @staticmethod
  def _process_stream_chunk(
      buf: bytearray,
      chunk: bytes,
      transform_fn: Callable[[bytes], Optional[bytes]],
  ) -> bytes:
    """Appends chunk to HDLC buffer, transforms complete frames, returns bytes."""
    buf.extend(chunk)
    out = bytearray()
    while True:
      try:
        flag_idx = buf.index(_HDLC_FLAG)
      except ValueError:
        break
      segment = bytes(buf[:flag_idx])
      del buf[: flag_idx + 1]
      if not segment:
        continue
      body = hdlc_decode_frame(segment)
      if body is None:
        # Fail-open: preserve raw segment if not a valid HDLC frame
        out.append(_HDLC_FLAG)
        out.extend(segment)
        out.append(_HDLC_FLAG)
        continue
      transformed = transform_fn(body)
      if transformed is not None:
        out.extend(hdlc_encode_frame(transformed))
    return bytes(out)

  def feed_host_to_rcp(self, chunk: bytes) -> bytes:
    return self._process_stream_chunk(
        self._host_rx_buf, chunk, self.transform_host_to_rcp
    )

  def feed_rcp_to_host(self, chunk: bytes) -> bytes:
    return self._process_stream_chunk(
        self._rcp_rx_buf, chunk, self.transform_rcp_to_host
    )

  @staticmethod
  def _flush_pending(fd: int, pending: bytearray) -> None:
    """Writes as much of pending to non-blocking fd as it accepts now."""
    while pending:
      try:
        written = os.write(fd, pending)
      except (BlockingIOError, InterruptedError):
        return
      except OSError as e:
        if e.errno == errno.EIO:
          return
        raise
      if written <= 0:
        return
      del pending[:written]

  def start(self, host_fd: int, rcp_fd: int) -> None:
    """Starts the bidirectional select() loop bridging host_fd and rcp_fd.

    Both fds are switched to non-blocking mode and each direction has its own
    output buffer, so a peer that stops reading stalls only its own direction
    (the source is no longer read once the backlog reaches
    _MAX_PENDING_BYTES) and the opposite direction keeps flowing.
    """
    self._stop_event.clear()
    logger = self._logger
    names = {host_fd: 'host', rcp_fd: 'rcp'}

    def _run_loop() -> None:
      fds = (host_fd, rcp_fd)
      peer = {host_fd: rcp_fd, rcp_fd: host_fd}
      feed = {host_fd: self.feed_host_to_rcp, rcp_fd: self.feed_rcp_to_host}
      pending = {host_fd: bytearray(), rcp_fd: bytearray()}  # bytes to write
      was_blocking = {}
      try:
        for fd in fds:
          was_blocking[fd] = os.get_blocking(fd)
          os.set_blocking(fd, False)
      except OSError as exc:
        logger.error('node %s: cannot set non-blocking: %s', self.node_id, exc)
        return
      reason = 'stop requested'
      try:
        while not self._stop_event.is_set():
          rlist = [
              fd for fd in fds if len(pending[peer[fd]]) < _MAX_PENDING_BYTES
          ]
          wlist = [fd for fd in fds if pending[fd]]
          try:
            readable, writable, _ = select.select(rlist, wlist, (), 0.05)
          except (OSError, ValueError) as exc:
            reason = f'select failed: {exc!r}'
            return
          for fd in writable:
            self._flush_pending(fd, pending[fd])
          for fd in readable:
            try:
              chunk = os.read(fd, 4096)
            except (BlockingIOError, InterruptedError):
              continue
            except OSError as e:
              if e.errno == errno.EIO:
                time.sleep(0.005)
                continue
              raise
            if not chunk:
              reason = f'EOF on {names[fd]} fd {fd}'
              return
            out = feed[fd](chunk)
            if out:
              dst = peer[fd]
              pending[dst].extend(out)
              self._flush_pending(dst, pending[dst])
      except OSError as exc:
        reason = f'I/O error: {exc!r}'
        return
      except Exception as exc:  # pylint: disable=broad-exception-caught
        reason = f'unexpected error: {exc!r}'
        raise
      finally:
        level = logger.info if reason == 'stop requested' else logger.error
        level(
            'node %s: Spinel relay stopped (%s); pending host=%dB rcp=%dB'
            ' tx_cnt=%d last_tid=%d rx_cnt=%d last_rx_seq=%d',
            self.node_id,
            reason,
            len(pending[host_fd]),
            len(pending[rcp_fd]),
            self._host_tx_frames,
            self._last_host_tid,
            self._rcp_rx_frames,
            self._last_rcp_mac_seq,
        )
        for fd, blocking in was_blocking.items():
          try:
            os.set_blocking(fd, blocking)
          except OSError as exc:
            _ = exc

    self._thread = Thread(
        target=_run_loop,
        name=f'SpinelHdlcRfProxy-{self.node_id}',
        daemon=True,
    )
    self._thread.start()

  def stop(self) -> None:
    self._stop_event.set()
    if self._thread is not None and self._thread.is_alive():
      self._thread.join(timeout=1.0)
    self._thread = None


_THREAD_SNIFFERS = {}


class ThreadSimPipe:
  __next_petition_id = 0
  __THREAD_GROUP_SIZE = 34
  __petition_mutex = Lock()
  # petition_id -> [ThreadRadioSniffer, number of open pipes]
  _sniffers = _THREAD_SNIFFERS
  __sniffers = _THREAD_SNIFFERS
  _ThreadSimPipe__sniffers = _THREAD_SNIFFERS
  __sniffer_mutex = Lock()

  @classmethod
  def get_next_petition(cls):
    with cls.__petition_mutex:
      cls.__next_petition_id += 1
      return cls.__next_petition_id

  def __init__(self, node_id, petition_id=0, rcp=False):
    self._user_slave_fd = None
    self.pipe_path_for_user = None
    self.node_id = node_id
    self.radio_fd = None
    self._proxy_sock = None
    self._spinel_proxy = None
    self.radio_process = None
    self.petition_id = petition_id
    self._has_sniffer = False
    self._is_rcp = bool(rcp)
    self.logger = CirqueLog.get_cirque_logger(self.__class__.__name__)
    if rcp:
      self.radio_command = 'ot-rcp'
    else:
      self.radio_command = 'ot-ncp-ftd'

  def open(self):
    master_fd, slave_fd = pty.openpty()
    _configure_raw_tty(master_fd)
    _configure_raw_tty(slave_fd)
    self._user_slave_fd = slave_fd
    self.pipe_path_for_user = os.ttyname(slave_fd)
    self.radio_fd = master_fd
    env = os.environ.copy()
    env['PORT_OFFSET'] = str(self.petition_id * self.__THREAD_GROUP_SIZE)
    self._acquire_sniffer(int(env['PORT_OFFSET']))
    command = [self.radio_command, '{}'.format(self.node_id)]
    self.logger.info(
        '-> Start virtual OpenThread Radio: command=%s, env=%s', command, env
    )
    if self._is_rcp:
      proxy_sock, rcp_sock = socket.socketpair(
          socket.AF_UNIX, socket.SOCK_STREAM
      )
      self._proxy_sock = proxy_sock
      try:
        self.radio_process = TaskRunner.post_task(lambda: subprocess.Popen(
            command,
            env=env,
            stdout=rcp_sock.fileno(),
            stdin=rcp_sock.fileno(),
            stderr=subprocess.DEVNULL)).wait()
      finally:
        rcp_sock.close()
      self._spinel_proxy = SpinelHdlcRfProxy(node_id=self.node_id)
      self._spinel_proxy.start(self.radio_fd, self._proxy_sock.fileno())
    else:
      self.radio_process = TaskRunner.post_task(lambda: subprocess.Popen(
          command,
          env=env,
          stdout=self.radio_fd,
          stdin=self.radio_fd,
          stderr=subprocess.DEVNULL)).wait()

  def _acquire_sniffer(self, port_offset):
    """Starts (or shares) the 802.15.4 sniffer of this pipe's petition."""
    pcap_dir = PcapCapability.get_active_pcap_dir()
    if not pcap_dir:
      return
    cls = ThreadSimPipe
    with cls.__sniffer_mutex:
      entry = cls.__sniffers.get(self.petition_id)
      if entry is None:
        port_base = int(os.environ.get('PORT_BASE', OT_SIM_DEFAULT_PORT_BASE))
        sniffer = ThreadRadioSniffer(
            os.path.join(pcap_dir, 'thread_{}.pcap'.format(self.petition_id)),
            ot_sim_radio_port(port_offset, port_base=port_base),
        )
        try:
          os.makedirs(pcap_dir, exist_ok=True)
          sniffer.start()
        except OSError as exc:
          self.logger.warning('Thread radio sniffer not started: %s', exc)
          return
        entry = cls.__sniffers[self.petition_id] = [sniffer, 0]
      entry[1] += 1
      self._has_sniffer = True

  def _release_sniffer(self):
    if not self._has_sniffer:
      return
    self._has_sniffer = False
    cls = ThreadSimPipe
    with cls.__sniffer_mutex:
      entry = cls.__sniffers.get(self.petition_id)
      if entry is None:
        return
      entry[1] -= 1
      if entry[1] <= 0:
        del cls.__sniffers[self.petition_id]
        entry[0].stop()

  def close(self):
    if self._spinel_proxy is not None:
      self._spinel_proxy.stop()
      self._spinel_proxy = None
    if self._proxy_sock is not None:
      try:
        self._proxy_sock.close()
      except OSError as exc:
        _ = exc
      self._proxy_sock = None
    if self.radio_process is not None:
      self.radio_process.terminate()
      try:
        self.radio_process.wait(timeout=2.0)
      except subprocess.TimeoutExpired:
        self.radio_process.kill()
        self.radio_process.wait(timeout=2.0)
      self.radio_process = None
    if self._user_slave_fd is not None:
      try:
        os.close(self._user_slave_fd)
      except OSError as exc:
        _ = exc
      self._user_slave_fd = None
    if self.radio_fd is not None:
      try:
        os.close(self.radio_fd)
      except OSError as exc:
        _ = exc
      self.radio_fd = None
    self._release_sniffer()
    if os.path.exists('./tmp'):
      shutil.rmtree('./tmp')

  def __del__(self):
    self.close()
