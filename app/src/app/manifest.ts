import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Sentinela — Pentest & Bug Bounty",
    short_name: "Sentinela",
    description: "Plataforma interna de pentest e bug bounty",
    start_url: "/",
    display: "standalone",
    background_color: "#060a07",
    theme_color: "#060a07",
    icons: [
      {
        src: "/icons/icon-192.png",
        sizes: "192x192",
        type: "image/png",
      },
      {
        src: "/icons/icon-512.png",
        sizes: "512x512",
        type: "image/png",
      },
    ],
  };
}
