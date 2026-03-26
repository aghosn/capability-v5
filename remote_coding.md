# 1. Create the mount point on your LLM machine
mkdir -p ~/remote_code

# 2. Mount with performance-boosting flags
sshfs user@hardware-ip:/path/to/remote/repo ~/remote_code \
  -o cache=yes \
  -o kernel_cache \
  -o auto_cache \
  -o compression=yes \
  -o reconnect \
  -o ServerAliveInterval=15 \
  -o ServerAliveCountMax=3
