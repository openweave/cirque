import unittest
import time
from cirque.connectivity.rf_channel_simulator import RfChannelSimulator, RfChannelConfig, RfFaultRule
from cirque.connectivity.threadsimpipe import SpinelHdlcRfProxy, _SPINEL_CMD_PROP_VALUE_IS, _SPINEL_PROP_STREAM_RAW, _SPINEL_CMD_PROP_VALUE_SET, _parse_802154_data_addrs

class TestThreadSimPipeFault(unittest.TestCase):
  def setUp(self):
    self.sim = RfChannelSimulator()
    self.sim.config.enabled = True
    self.proxy = SpinelHdlcRfProxy(node_id=1, simulator=self.sim)

  def test_sigma2_blackhole(self):
    self.sim.config.fault_rule = RfFaultRule(
        rule='sigma2_blackhole',
        src_ext='1122334455667788',
        src_short='8c01',
        window_s=2.0,
        psdu_threshold=100
    )
    
    psdu = b'\x61\xdc\x00\x22\x22' + bytes.fromhex('8877665544332211') + bytes.fromhex('8877665544332211') 
    frame = bytes([0x80, _SPINEL_CMD_PROP_VALUE_SET, _SPINEL_PROP_STREAM_RAW, len(psdu)&0xff, (len(psdu)>>8)&0xff]) + psdu + b'\x00'*10
    
    self.assertEqual(self.sim.config.fault_rule.trigger_time, 0.0)
    out = self.proxy.transform_host_to_rcp(frame)
    self.assertEqual(out, frame, "Host->RCP should never be dropped")
    self.assertGreater(self.sim.config.fault_rule.trigger_time, 0.0)
    
    # Extended address (fcf1=0xdc)
    psdu_large = b'\x61\xdc\x00\x22\x22' + bytes.fromhex('8877665544332211') + bytes.fromhex('8877665544332211') + b'\x00'*100
    frame_large = bytes([0x80, _SPINEL_CMD_PROP_VALUE_IS, _SPINEL_PROP_STREAM_RAW, len(psdu_large)&0xff, (len(psdu_large)>>8)&0xff]) + psdu_large + b'\x00'*10
    
    out_drop = self.proxy.transform_rcp_to_host(frame_large)
    self.assertIsNone(out_drop)

    psdu_small = b'\x61\xdc\x00\x22\x22' + bytes.fromhex('8877665544332211') + bytes.fromhex('8877665544332211') + b'\x00'*50
    frame_small = bytes([0x80, _SPINEL_CMD_PROP_VALUE_IS, _SPINEL_PROP_STREAM_RAW, len(psdu_small)&0xff, (len(psdu_small)>>8)&0xff]) + psdu_small + b'\x00'*10
    out_small = self.proxy.transform_rcp_to_host(frame_small)
    self.assertIsNotNone(out_small)
    
    # Short address (fcf1=0x98, dest_mode=2, src_mode=2)
    psdu_short_large = b'\x61\x98\x00\x22\x22' + bytes.fromhex('7788') + bytes.fromhex('018c') + b'\x00'*100
    frame_short_large = bytes([0x80, _SPINEL_CMD_PROP_VALUE_IS, _SPINEL_PROP_STREAM_RAW, len(psdu_short_large)&0xff, (len(psdu_short_large)>>8)&0xff]) + psdu_short_large + b'\x00'*10
    out_short_drop = self.proxy.transform_rcp_to_host(frame_short_large)
    self.assertIsNone(out_short_drop)

if __name__ == '__main__':
  unittest.main()
