import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  experimental: {
    // Vinext checks multipart requests as possible server actions before API
    // routing. Allow a 10 MiB ZIP plus multipart fields and headers.
    serverActions: { bodySizeLimit: "11mb" },
  },
};

export default nextConfig;
