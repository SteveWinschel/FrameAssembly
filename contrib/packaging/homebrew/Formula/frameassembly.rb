class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.2.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.2/frameassembly-macos-arm64.tar.gz"
      sha256 "ae3732c064fcf5cb2b579fb8a03569b9f7fcbcc8cf5738e956b7009bc92d4b79"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.2/frameassembly-macos-x64.tar.gz"
      sha256 "042b53981c661c9657d410bac338e390b9b7425a4dbf183362b1e90e9a43d4e9"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.2/frameassembly-linux-arm64.tar.gz"
      sha256 "bc4ef6ae35f1f03965dc518b4436ed7121fa3c38ce3b93d01f1887b9a305c758"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.2.2/frameassembly-linux-x64.tar.gz"
      sha256 "7ba5d0277083db5c5b766a64f69deda4a49477e991b5e5a3e9ef77306a4ee081"
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
    assert_match "frameassembly 3.2.2", shell_output("#{bin}/frameassembly version")
  end
end
