class Frameassembly < Formula
  desc "Rootless Packets-as-Code DSL & compiler for deterministic PCAP/PCAPNG traffic"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "1.4.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.3/frameassembly-v1.4.3-aarch64-apple-darwin.tar.gz"
      sha256 "69b2a3d970e0d684fca77e30542d74d5ebb4ba91e25e56f90125bc476bdeae57"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.3/frameassembly-v1.4.3-x86_64-apple-darwin.tar.gz"
      sha256 "ac54925b14326470eaa55fef65e514f921df6c765076ef558d76023a51184d45"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.3/frameassembly-v1.4.3-aarch64-unknown-linux-musl.tar.gz"
      sha256 "781c9b730560f2241900e9c478759fe66794823cc95291702068cb18d52a7e9b"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.3/frameassembly-v1.4.3-x86_64-unknown-linux-musl.tar.gz"
      sha256 "01cbaaa16a8eb2053f92dc84328ae611fe0c5d3f96db329f6395fd6ef35bb108"
    end
  end

  def install
    bin.install "frameassembly"
    doc.install "README.md" if File.exist?("README.md")
  end

  test do
    assert_match "frameassembly 1.4.3", shell_output("#{bin}/frameassembly --version")
  end
end
