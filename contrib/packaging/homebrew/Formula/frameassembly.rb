class Frameassembly < Formula
  desc "Rootless Packets-as-Code DSL & compiler for deterministic PCAP/PCAPNG traffic"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "1.5.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-aarch64-apple-darwin.tar.gz"
      sha256 "3c1a73c361d075280cdb98130d4e7b42ad87a75735ba17e03e6f1f455a9672f2"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-x86_64-apple-darwin.tar.gz"
      sha256 "c1b335ec79820e81363982027758a2eed0ae0e2850059e49df32e6e5350b6a40"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-aarch64-unknown-linux-musl.tar.gz"
      sha256 "a4472628274aad6400364d21b34905654422ce453849b53ccc1d9556eadac576"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-x86_64-unknown-linux-musl.tar.gz"
      sha256 "1d0a47e1df66deea8f5a7e4f6dde94446504a864c68de397a81309cc3581efd7"
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
