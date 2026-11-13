class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.0.0/frameassembly-macos-arm64.tar.gz"
      sha256 "bb5ede58b43af68b631d157720e9529bc0f9091748757c60a4dc24c2592e23ea"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.0.0/frameassembly-macos-x64.tar.gz"
      sha256 "5eceb609593449c19e078d84a6c95e5a4908885c3c5d43ff3e7e6ec081d504d6"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.0.0/frameassembly-linux-arm64.tar.gz"
      sha256 "cd5682608b9056298295ce44ce21cd0783f4b38f869933df9212fb0fd6bb39a9"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.0.0/frameassembly-linux-x64.tar.gz"
      sha256 "26dc8ce746ccd96f87d5b8f7f278d761c3c36592e26f6da3f657b85e87e97d4e"
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
