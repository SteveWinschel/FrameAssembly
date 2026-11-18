class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.1.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.2/frameassembly-macos-arm64.tar.gz"
      sha256 "a8b9c3c9b28536d9b79a2265c997e249c503a557861c0ac71613da01ec423d6e"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.2/frameassembly-macos-x64.tar.gz"
      sha256 "7648b56d7eef96863626e0ed2263e5d45bdc35a6a31e6664ff1556712e526c20"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.2/frameassembly-linux-arm64.tar.gz"
      sha256 "fe8bf7e69315dec66911184448f2de4d99bde79563c01d029d386fa2098ce866"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.2/frameassembly-linux-x64.tar.gz"
      sha256 "60cbda68e5f879e9459e25893a359fa3614903344fda6a95f890e2210e00d272"
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
    assert_match "frameassembly 3.1.2", shell_output("#{bin}/frameassembly version")
  end
end
