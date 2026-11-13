class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.0.0/frameassembly-macos-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.0.0/frameassembly-macos-x64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.0.0/frameassembly-linux-arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.0.0/frameassembly-linux-x64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
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
    assert_match "frameassembly 3.0.0", shell_output("#{bin}/frameassembly version")
  end
end
