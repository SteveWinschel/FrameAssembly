# Step 2: Preview the packet ladder

The **Live Packet Ladder** shows what your `.frasm` code puts on the wire before you write a single file.

1. Open a `.frasm` file.
2. Click the split-view icon in the editor title bar, or run **FrameAssembly: Show Live Packet Ladder Preview** from the Command Palette (`Ctrl+Shift+P`).
3. Edit your code. The panel refreshes as you type.

Each row lists the frame number, relative time in milliseconds, source and destination, protocol, length, and a one-line summary such as `Echo Request (type=8 code=0)`. Click a row to expand the raw Ethernet frame as a hex dump.

If the code has an error, the editor underlines the exact spot and the ladder keeps the last good result, with the compiler message shown on top.

On `vscode.dev` and `github.dev` the ladder panel also offers a **Download .pcap** button, because browser-based editors cannot always write next to your file.
