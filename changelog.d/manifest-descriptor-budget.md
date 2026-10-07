### Fixed: tool descriptors stay within the manifest size the platform accepts

- The sensor manifest carries at most 128 KiB of tool descriptors in all (`core.MaxManifestDescriptorBytes`). Past it, the largest descriptors are left out, deterministically. Those tools keep their digest and contract fields, and the platform plans with them as before. Without the budget, a sensor with many large descriptors could exceed the platform manifest cap (256 KiB in OpenCTEM), and its manifest would be refused.
