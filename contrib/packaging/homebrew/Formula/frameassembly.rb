class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.2.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.1/frameassembly-macos-arm64.tar.gz"
      sha256 "72cf54e24178d3616396a2244265e1e1edc049b95854ef0767a71a6168c7bf0d"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.1/frameassembly-macos-x64.tar.gz"
      sha256 "c808a232819f629419734ef4aa48c3b7c21b5af4cdf0c483b116bc2a8ab1f965"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.1/frameassembly-linux-arm64.tar.gz"
      sha256 "a6e7f0f949167e2f1a64e74a5a088b32c177d0e2018a56a825d59d26dd3076e8"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.1/frameassembly-linux-x64.tar.gz"
      sha256 "a49d894a4ed422916888e5623d7fa592a6d33dc48ffa96cd264e64f8004f2500"
    end
  end

  def install
    bin.install "frameassembly"
    doc.install "README.md" if File.exist?("README.md")
    pkgshare.install "quickstart.frasm" if File.exist?("quickstart.frasm")
    if Dir.exist?("completions")
      bash_completion.install "completions/frameassembly.bash" => "frameassembly" if File.exist?("completions/frameassembly.bash")
      zsh_completion.install "completions/_frameassembly" => "_frameassembly" if File.exist?("completions/_frameassembly")
      fish_completion.install "completions/frameassembly.fish" if File.exist?("completions/frameassembly.fish")
    end
  end

  test do
    assert_match "frameassembly 3.2.1", shell_output("#{bin}/frameassembly version")
  end
end
