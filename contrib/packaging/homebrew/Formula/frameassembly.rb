class Frameassembly < Formula
  desc "Rootless Packets-as-Code DSL & compiler for deterministic PCAP/PCAPNG traffic"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "1.4.6"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-aarch64-apple-darwin.tar.gz"
      sha256 "4cce9733621b37d5468554938d9e5bbcc90bfda17d711bafe13460548c2b162a"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-x86_64-apple-darwin.tar.gz"
      sha256 "5edfc8df8ea34dbc7de9d77224b65c102111fa5073d0c4b5eef57f30aad79ee1"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-aarch64-unknown-linux-musl.tar.gz"
      sha256 "1fd55e0fac8db9348ddbb780c8121c04bedc84db6b746f974f824b1a123a4f1d"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v1.4.6/frameassembly-v1.4.6-x86_64-unknown-linux-musl.tar.gz"
      sha256 "6cfe0026d19c7604bf9aa10ff065f3799568c00d4c6b6b6b68ec28506b05e850"
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
