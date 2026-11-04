class Frameassembly < Formula
  desc "Rootless Packets-as-Code DSL & compiler for deterministic PCAP/PCAPNG traffic"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "1.4.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.5/frameassembly-v1.4.5-aarch64-apple-darwin.tar.gz"
      sha256 "509aced9ed13c355e4d793948be2eab20233005ff00541d3033e40b499c35058"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.5/frameassembly-v1.4.5-x86_64-apple-darwin.tar.gz"
      sha256 "c1a5c47b836bfecafbcdaa608771019b7304c19af4ddadc0c988148e7aa9e2e5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.5/frameassembly-v1.4.5-aarch64-unknown-linux-musl.tar.gz"
      sha256 "65edd498b253b7176b88a0461c4025f3684e9c39b5ea6cf9715df100db7f68a5"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.5/frameassembly-v1.4.5-x86_64-unknown-linux-musl.tar.gz"
      sha256 "c062515075cb56d7364737bd0f3522fab75944c40eee9df7091e81f0c8990e73"
    end
  end

  def install
    bin.install "frameassembly"
    doc.install "README.md" if File.exist?("README.md")
  end

  test do
    assert_match "frameassembly 1.4.5", shell_output("#{bin}/frameassembly --version")
  end
end
