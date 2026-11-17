class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.1.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.1/frameassembly-macos-arm64.tar.gz"
      sha256 "759bb8828b20e1ea22da1f344681f31e19b3a9bdfa32dcdcabcaf38ce72c2ec2"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.1/frameassembly-macos-x64.tar.gz"
      sha256 "ceadb1f959591b33eda79168e8586388ff2540c34c16e5a7848c2f6900d0b190"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.1/frameassembly-linux-arm64.tar.gz"
      sha256 "5908de213ec385d05c10aea81d92c92bb1dc943e2eb2c1f1f8699e5caae9ac0f"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.1/frameassembly-linux-x64.tar.gz"
      sha256 "41b8f1b61e2303428ca6b0eac22cc4de548a781d8bd5dcf6c50fbd38aaffe30e"
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
    assert_match "frameassembly 3.1.1", shell_output("#{bin}/frameassembly version")
  end
end
