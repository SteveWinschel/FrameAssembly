class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.0/frameassembly-macos-arm64.tar.gz"
      sha256 "6a9a79c3a8973f347927aaddec04fa5155a8b1ccfa6f6c3b75657c5bccfdfcc7"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.0/frameassembly-macos-x64.tar.gz"
      sha256 "4097fee5f589f076a5dda222f1ba0fb93779fd03ab99c003fa99d46f4447b3ed"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.0/frameassembly-linux-arm64.tar.gz"
      sha256 "a029d6726d2e74d349fa78d5a27d6a55262bf49392d2a45c073d57935b16ba09"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.0/frameassembly-linux-x64.tar.gz"
      sha256 "ee6c2a9e71654ca9b4a397a47231f3264d09e1a1cc275e1a0f11c32f2c44c0ef"
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
    assert_match "frameassembly 3.2.0", shell_output("#{bin}/frameassembly version")
  end
end
