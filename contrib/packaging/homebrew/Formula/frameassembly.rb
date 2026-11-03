class Frameassembly < Formula
  desc "Rootless Packets-as-Code DSL & compiler for deterministic PCAP/PCAPNG traffic"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "1.4.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.4/frameassembly-v1.4.4-aarch64-apple-darwin.tar.gz"
      sha256 "f42287ddc5132b1c0cabf22a4e624c4a0444ab539a8af571491789c76a6626a9"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.4/frameassembly-v1.4.4-x86_64-apple-darwin.tar.gz"
      sha256 "c72bd90645737616d729ed127b72490c96f55eb4ce61e53e53192caf2dbefbe0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.4/frameassembly-v1.4.4-aarch64-unknown-linux-musl.tar.gz"
      sha256 "b13eaaea5817ef810e8be86fd0bc010ef1f4828151bb0070b335e864da29f817"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.4/frameassembly-v1.4.4-x86_64-unknown-linux-musl.tar.gz"
      sha256 "eb2ab5f2f9cd32bb10f8ba48249c0706221b93390977973be4968cffc6cc4eba"
    end
  end

  def install
    bin.install "frameassembly"
    doc.install "README.md" if File.exist?("README.md")
  end

  test do
    assert_match "frameassembly 1.4.4", shell_output("#{bin}/frameassembly --version")
  end
end
