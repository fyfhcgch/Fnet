"""Unit tests for the WPA/PMKID helpers (no tshark needed)."""
from __future__ import annotations

import unittest

from fnet.features import wifi


class WifiHelperTest(unittest.TestCase):
    def test_normalize_mac(self):
        self.assertEqual(wifi.normalize_mac("AA:BB:CC:DD:EE:FF"),
                         "aabbccddeeff")
        self.assertEqual(wifi.normalize_mac("aa-bb-cc-dd-ee-ff"),
                         "aabbccddeeff")
        self.assertEqual(wifi.normalize_mac("aabbccddeeff"),
                         "aabbccddeeff")
        self.assertEqual(wifi.normalize_mac("not-a-mac"), "")

    def test_normalize_pmkid(self):
        value = "00112233445566778899aabbccddeeff"
        self.assertEqual(wifi.normalize_pmkid(value.upper()), value)
        self.assertEqual(wifi.normalize_pmkid("00:11:22:33"), "")

    def test_pmkid_hash(self):
        line = wifi.pmkid_hash(
            "00112233445566778899aabbccddeeff",
            "AABBCCDDEEFF", "112233445566", "test-ssid")
        self.assertEqual(
            line,
            "WPA*01*00112233445566778899aabbccddeeff*aabbccddeeff*112233445566*"
            "746573742d73736964***")
        self.assertEqual(wifi.pmkid_hash("bad", "aabbccddeeff",
                                         "112233445566", "ssid"), "")

    def test_handshake_state(self):
        self.assertEqual(wifi.handshake_state([1, 2, 3, 4]),
                         "完整握手 (M1-M4)")
        self.assertEqual(wifi.handshake_state([1, 2, 4]),
                         "握手可用 (M1/M2)")
        self.assertIn("M1", wifi.handshake_state([3, 4]))
        self.assertEqual(wifi.handshake_state([]), "无 EAPOL 消息")

    def test_hashcat_recipe(self):
        recipe = wifi.hashcat_recipe("/tmp/cap.pcap", "/tmp/words.txt")
        text = "\n".join(recipe)
        self.assertIn("hcxpcapngtool -o wifi.hc22000 /tmp/cap.pcap", text)
        self.assertIn("hashcat -m 22000 -a 0 wifi.hc22000 /tmp/words.txt", text)
        self.assertIn("--show", text)

    def test_hashcat_recipe_quotes_spaces(self):
        recipe = wifi.hashcat_recipe(
            "/tmp/my capture.pcap", "/tmp/my words.txt")
        text = "\n".join(recipe)
        self.assertIn("'/tmp/my capture.pcap'", text)
        self.assertIn("'/tmp/my words.txt'", text)


class EapolDeepTest(unittest.TestCase):
    def _message(self, **kwargs):
        from fnet.utils import wifi as wifilib

        defaults = dict(frame="1", bssid="aabbccddeeff",
                        station="112233445566", ssid="testnet",
                        message=1, key_info=wifilib.KEY_INFO_ACK,
                        nonce=b"\x01" * 32, mic=b"", key_data=b"",
                        replay=1)
        defaults.update(kwargs)
        return wifilib.EapolMessage(**defaults)

    def test_parse_pmkid_kde(self):
        from fnet.utils import wifi as wifilib

        blob = ("dd14000fac04" + "00112233445566778899aabbccddeeff")
        self.assertEqual(
            wifilib.parse_pmkid_kde(blob),
            ["00112233445566778899aabbccddeeff"])
        self.assertEqual(
            wifilib.parse_pmkid_kde("00112233445566778899aabbccddeeff"),
            ["00112233445566778899aabbccddeeff"])
        self.assertEqual(wifilib.parse_pmkid_kde("deadbeef"), [])

    def test_eapol_from_values(self):
        from fnet.utils import wifi as wifilib

        values = {
            "frame.number": "7",
            "wlan.bssid": "aa:bb:cc:dd:ee:ff",
            "wlan.ta": "aa:bb:cc:dd:ee:ff",
            "wlan.ra": "11:22:33:44:55:66",
            "wlan_rsna_eapol.keydes.key_info": "0x0092",
            "wlan_rsna_eapol.keydes.nonce": "01" * 32,
            "wlan_rsna_eapol.keydes.data": (
                "dd14000fac04" + "00112233445566778899aabbccddeeff"),
        }
        message = wifilib.eapol_from_values(values)
        self.assertIsNotNone(message)
        self.assertEqual(message.message, 1)
        self.assertEqual(message.bssid, "aabbccddeeff")
        self.assertEqual(message.station, "112233445566")
        self.assertTrue(message.ack)
        self.assertFalse(message.has_mic)
        self.assertEqual(message.pmkids,
                         ["00112233445566778899aabbccddeeff"])

    def test_message_number_from_key_info(self):
        from fnet.utils import wifi as wifilib

        self.assertEqual(wifilib.message_number(0x0092, has_mic=False), 1)
        self.assertEqual(wifilib.message_number(0x0112, has_mic=True), 2)
        self.assertEqual(wifilib.message_number(0x03A2, has_mic=True), 3)
        self.assertEqual(wifilib.message_number(0x0302, has_mic=True), 4)

    def test_reconstructed_eapol_and_hash(self):
        from fnet.utils import wifi as wifilib

        m1 = self._message(
            message=1, nonce=b"\x01" * 32,
            key_data=bytes.fromhex("dd14000fac04" + "ab" * 16))
        m2 = self._message(
            message=2, key_info=wifilib.KEY_INFO_MIC,
            nonce=b"\x02" * 32, mic=b"\x33" * 16)
        frame = m2.eapol_frame(zero_mic=True)
        self.assertEqual(frame[0], 2)
        self.assertEqual(frame[1], 3)
        self.assertEqual(frame[4], 2)  # key descriptor type
        self.assertIn(b"\x00" * 16, frame)
        line = wifilib.eapol_hash([m1, m2], "testnet")
        self.assertTrue(line.startswith("WPA*02*33333333333333333333333333333333*aabbccddeeff*112233445566"))
        self.assertIn("*746573746e6574*", line)
        self.assertIn("*" + "01" * 32 + "*", line)
        self.assertIn("*" + "02" * 32 + "*", line)
        self.assertTrue(line.endswith("*00"))

    def test_incomplete_handshake_has_no_hash(self):
        from fnet.utils import wifi as wifilib

        m1 = self._message(message=1, nonce=b"\x01" * 32)
        self.assertEqual(wifilib.handshake_state([1]), "握手不完整，缺少 M2/M3/M4")
        self.assertEqual(wifilib.eapol_hash([m1]), "")
        self.assertIsNone(wifilib.usable_pair([m1]))

    def test_pmkid_entries_dedupe(self):
        from fnet.utils import wifi as wifilib

        pmkid = "ab" * 16
        first = self._message(message=1, pmkids=[pmkid])
        second = self._message(frame="2", message=1, pmkids=[pmkid])
        other = self._message(frame="3", bssid="001122334455",
                              station="66778899aabb", pmkids=[pmkid])
        entries = wifilib.pmkid_entries([first, second, other])
        self.assertEqual(len(entries), 2)
        self.assertEqual({entry[1] for entry in entries},
                         {"aabbccddeeff", "001122334455"})

    def test_sae_akm_detection(self):
        from fnet.utils import wifi as wifilib

        self.assertEqual(wifilib.sae_akms("00-0f-ac-8,00-0f-ac-2"), [8])
        self.assertEqual(wifilib.sae_akms("00-0f-ac-2"), [])
        text = wifilib.sae_path([8])
        self.assertIn("WPA3/SAE", text)
        self.assertIn("Dragonfly", text)
        self.assertEqual(wifilib.sae_path([]), "")

    def test_ssid_text(self):
        from fnet.utils import wifi as wifilib

        self.assertEqual(wifilib.ssid_text("746573746e6574"), "testnet")
        self.assertEqual(wifilib.ssid_text("testnet"), "testnet")

    def test_hcxtools_recipe_shape(self):
        from fnet.utils import wifi as wifilib

        text = "\n".join(wifilib.hcxtools_recipe("/tmp/cap.pcap"))
        self.assertIn("hashcat -m 22000", text)
        self.assertIn("/tmp/cap.pcap", text)


if __name__ == "__main__":
    unittest.main()
