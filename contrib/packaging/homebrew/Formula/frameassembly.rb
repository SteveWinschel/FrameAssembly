class Frameassembly < Formula
  desc "Rootless Packets-as-Code DSL & compiler for deterministic PCAP/PCAPNG traffic"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "1.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-aarch64-apple-darwin.tar.gz"
      sha256 "132d7d36517ef4fb6ea0a5459604015bb3bdffbb04ec038f45ceee217637f9a2"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-x86_64-apple-darwin.tar.gz"
      sha256 "6497c3aacf7eaece87a97bb53024ad9042ed10a738454c8aaa626892142f3fdb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-aarch64-unknown-linux-musl.tar.gz"
      sha256 "31a7f286ff9fc6b217286ee3f4bb5946e8ba591dd678b1b6162de3de91e1cacb"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-x86_64-unknown-linux-musl.tar.gz"
      sha256 "8dce0bfcf0c7a5e384c507fb7220b52b332e818bd2441025de3dd1db2bd1de7f"
    end
  end

  def install
    bin.install "frameassembly"
    doc.install "README.md" if File.exist?("README.md")
  end

  test do
    assert_match "frameassembly 1.4.6", shell_output("#{bin}/frameassembly --version")
  end
end
