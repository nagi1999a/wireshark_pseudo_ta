# wireshark_pseudo_ta
A Lua plugin for Wireshark to show inferred/pseudo transmitter address for ACK, CTS, ..., with a single field for filtering ta&amp;ra.
Inspired by and Modified from [wireshark-tcpextend](https://github.com/gaddman/wireshark-tcpextend)

## About
Some protocols in 802.11 do not have transmitter fields because we do not need them. However, it may sometimes cause annoying things while analyzing sniffer logs. For example, we may need to include ACK frames to know whether the receiver has received a frame between the traffic of STA1 & STA2. But since the ACK frame does not have a transmitter address, we cannot simply use a display filter like `(wlan.addr == <STA1>) && (wlan.addr == <STA2>)`. When we include ACKs by extends the filter with `((wlan.ra == <STA1>) || (wlan.ra == <STA2>)) && (wlan.fc.type_subtype == 0x001d)`, all Acks that may not issue by STA1 or STA2 will be included.

The plugin will first check whether the `wlan.ta` field exists. If it exists, it will directly use the value as `p-ta.ta`. Otherwise, it will try to infer a pseudo transmitter address as `p-ta.ta`, when the transmitter of the previous frame is equal to the receiver of the current frame. It also provides an additional field that contains the transmitter and receiver address. Thus, when we want to filter the traffic between STA1 & STA2 with ACKs included, we can write a much shorter filter `(p-ta.addr == <STA1>) && (p-ta.addr == <STA2>)`.

If there are any questions or bugs, please feel free to open up the issues!

## Functionality
1. Provide a pseudo transmitter address based on the previous frame.
2. Provide a field to distinguish whether the address is pseudo.
3. Provide an additional field to combine the transmitter and receiver addresses.

## Support types
1. ACK
2. RTS-CTS
3. CTS-to-self

## How to use
Place the Lua script in [Wireshark Plugin Folder](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) and restart Wireshark.

## Fields
| Field            | Type    | Meaning                                                                |
|------------------|---------|------------------------------------------------------------------------|
| p-ta.ta          | address | Transmitter Address                                                    |
| p-ta.taStr       | string  | String of Transmitter Address <br> with parentheses to indicate pseudo |
| p-ta.isPseudo    | bool    | Is Pseudo                                                              |
| p-ta.isPseudoStr | string  | String to indicate pseudo                                              |
| p-ta.addr        | address | TA & RA$^{[1]}$     |

[1]: The plugin will try to contain the RA of the next frame for CTS-to-self frames. However, since live capture has a different 2-pass dissector process, `p-ta.addr` will not guarantee the RA of the next frame will be included. The same situation appears when reloading the Lua script using `Analyze > Reload Lua Plugins` when there is a display filter set.

## Screenshot
Pcap (`Network_Join_Nokia_Mobile.pcap`) is from [Wireshark Wiki](https://wiki.wireshark.org/SampleCaptures#wifi-wireless-lan-captures-80211)
![Screenshot](screenshot.png)