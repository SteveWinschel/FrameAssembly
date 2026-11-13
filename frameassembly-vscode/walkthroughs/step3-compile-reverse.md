# Step 3: Compile to `.pcap` or reverse a capture

## Compile `.frasm` to `.pcap`

Click the package icon in the editor title bar, right-click a `.frasm` file in the Explorer, or run **FrameAssembly: Compile .frasm to .pcap**. The capture is written next to your file as `<name>.pcap` with nanosecond timestamps.

When it finishes, the notification offers two buttons:

* **Open Capture** opens the file with your default application, usually Wireshark.
* **Reveal in Explorer** shows the file in your operating system's file manager.

From there, replay it with `tcpreplay`, feed it to Suricata or Zeek, or check what your monitoring tool does with it.

## Reverse a capture back to `.frasm`

Right-click any `.pcap` or `.pcapng` file in the Explorer and choose **FrameAssembly: Reverse Capture (.pcap/.pcapng) to .frasm**. The capture is decompiled into `.frasm` code with `host1`, `host2`, and so on, and opens in a new tab. Change one field, compile it again, and you have an edited capture.

Prefer the command line? The companion CLI does the same:

* `frameassembly demo.frasm`
* `frameassembly show demo.frasm`
* `frameassembly reverse capture.pcap`

More examples and protocol guides: <https://github.com/SteveWinschel/FrameAssembly>. No install needed to try it in a browser: <https://frameassembly.ai.studio/>.
