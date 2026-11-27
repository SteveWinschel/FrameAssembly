class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.3.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.3.1/frameassembly-macos-arm64.tar.gz"
      sha256 "3f4e50027de40d4eca9961a7adfce07456cc841cca0ba1b7a5014ce0549bdd1f"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.3.1/frameassembly-macos-x64.tar.gz"
      sha256 "56eee09f40bd0b47102fb5af1234d3d92065f1962e33c25adc47c9e50a800813"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.3.1/frameassembly-linux-arm64.tar.gz"
      sha256 "6d834ec89057b370bcd84316212d8f0eae43e0cb4fe74679923d1e4b118aaa56"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.3.1/frameassembly-linux-x64.tar.gz"
      sha256 "8b226fc3d38bc05ce71d15ae2c9fc5c5603fb7539afcb7c835b0cd93656a5d68"
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
    assert_match "frameassembly 3.3.1", shell_output("#{bin}/frameassembly version")
  end
end
