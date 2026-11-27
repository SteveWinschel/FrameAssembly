class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.3.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.3.1/frameassembly-macos-arm64.tar.gz"
      sha256 "f8f5477d80337231b07ebb8cdd8f3f197826b5a94ea58e99f4a699f74310ff5c"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.3.1/frameassembly-macos-x64.tar.gz"
      sha256 "84e055c4a122bd5d7c077ad643d27642438da79edc06e7c89e39d7712f194dcb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.3.1/frameassembly-linux-arm64.tar.gz"
      sha256 "06dc998106bb787b966822e70d34e6d4a08e0f45f036678f1d3f78172e1621cb"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.3.1/frameassembly-linux-x64.tar.gz"
      sha256 "b9650f983e3c8e2a22e95bbce14df38093d9cb0824985c267a499ad877024194"
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
