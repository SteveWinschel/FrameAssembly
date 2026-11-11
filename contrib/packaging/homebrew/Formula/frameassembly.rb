class Frameassembly < Formula
  desc "Compile .fasm network traffic code to .pcap/.pcapng and reverse captures"
  homepage "https://github.com/SteveWinschel/FrameAssembly"
  version "2.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v2.0.0/frameassembly-v2.0.0-aarch64-apple-darwin.tar.gz"
      sha256 "c4391691e1840bf74475143386055d0d787927b6cbb12a425a47d8293c579fb1"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v2.0.0/frameassembly-v2.0.0-x86_64-apple-darwin.tar.gz"
      sha256 "ee5492b38d4fdbbb64181affb41e174ab1ebba1fa9b50cae2d0e6e401597e93d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v2.0.0/frameassembly-v2.0.0-aarch64-unknown-linux-musl.tar.gz"
      sha256 "8af415551ccfaa57b63b982955e76f5e957e48a1693bf0321919ba54eb5e6a93"
    else
      url "https://github.com/SteveWinschel/FrameAssembly/releases/download/v2.0.0/frameassembly-v2.0.0-x86_64-unknown-linux-musl.tar.gz"
      sha256 "b9a98d9d4716695c16aac9387bffcefba5bfdf568490a9541a88e9deb16b9333"
    end
  end

  def install
    bin.install "frameassembly"
    doc.install "README.md" if File.exist?("README.md")
    if Dir.exist?("completions")
      bash_completion.install "completions/frameassembly.bash" => "frameassembly" if File.exist?("completions/frameassembly.bash")
      zsh_completion.install "completions/_frameassembly" => "_frameassembly" if File.exist?("completions/_frameassembly")
      fish_completion.install "completions/frameassembly.fish" if File.exist?("completions/frameassembly.fish")
    end
  end

  test do
    assert_match "frameassembly 2.0.0", shell_output("#{bin}/frameassembly version")
  end
end
