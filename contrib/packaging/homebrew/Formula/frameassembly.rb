class Frameassembly < Formula
  desc "Rootless Packets-as-Code DSL & compiler for deterministic PCAP/PCAPNG traffic"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "1.4.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.2/frameassembly-v1.4.2-aarch64-apple-darwin.tar.gz"
      sha256 "ccb40f5b2e947478ff2f6e0147a8c6f9508d27c234c93155e9e7586eb69e70b4"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.2/frameassembly-v1.4.2-x86_64-apple-darwin.tar.gz"
      sha256 "483a7624e3f3329063e555ae1bb7a5937b8f860146090a7d7b6f475a6b4eefd1"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.2/frameassembly-v1.4.2-aarch64-unknown-linux-musl.tar.gz"
      sha256 "48aca5a545990a43c5e68cb25a0ef14a25ca8d477b8794b55d9d1f82da4a193a"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.2/frameassembly-v1.4.2-x86_64-unknown-linux-musl.tar.gz"
      sha256 "4cb915ac7a15e5ff5ddd8b41b5099dd1362fa90f738b7bc7c73ec9f2bb2810e1"
    end
  end

  def install
    bin.install "frameassembly"
    doc.install "README.md" if File.exist?("README.md")
  end

  test do
    assert_match "frameassembly 1.4.2", shell_output("#{bin}/frameassembly --version")
  end
end
