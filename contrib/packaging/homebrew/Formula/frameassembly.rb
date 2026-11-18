class Frameassembly < Formula
  desc "Compile .frasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "3.1.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.2/frameassembly-macos-arm64.tar.gz"
      sha256 "792371294b70b7ff92592d7a5d700073d06c9219f7fb42a0aa6bd102cb37d159"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.2/frameassembly-macos-x64.tar.gz"
      sha256 "726bac788bfb8814ec42f8cfb705d655a768c788e109c56b1f0262f471713966"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.2/frameassembly-linux-arm64.tar.gz"
      sha256 "eea7aa38941346fcaded614e864e8cae588ce7551bc4c8e6e809c5eab93edba8"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v3.1.2/frameassembly-linux-x64.tar.gz"
      sha256 "852ce4145f1b9a19f19debf0763012cfa2881917e2dcb9d87922b242ed6530ad"
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
