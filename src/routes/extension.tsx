import { createFileRoute } from "@tanstack/react-router";
import { PageHeader } from "@/components/PageHeader";

export const Route = createFileRoute("/extension")({
  head: () => ({
    meta: [
      { title: "Download SafeScan AI for your desktop" },
      { name: "description", content: "Download SafeScan AI for Windows — a floating shield that checks links, SMS, emails, QR codes and selected text for scams." },
      { property: "og:title", content: "SafeScan AI on your desktop" },
      { property: "og:description", content: "Your AI shield against digital scams, running on your own computer." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Ext,
});

function download() {
  fetch("/safescan-desktop.zip")
    .then((r) => {
      if (!r.ok) throw new Error(`Download failed: ${r.status}`);
      return r.blob();
    })
    .then((b) => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(b);
      a.download = "safescan-desktop.zip";
      a.click();
      URL.revokeObjectURL(a.href);
    })
    .catch((e) => alert(e.message));
}

function Ext() {
  return (
    <div className="mx-auto max-w-3xl px-4 py-12">
      <PageHeader
        icon="🛡️"
        title="SafeScan AI on your desktop"
        subtitle="A shield that sits on top of everything else on your computer and checks what you're looking at before you trust it."
      />

      <div className="glass mt-8 rounded-2xl p-6">
        <h2 className="font-display text-xl font-semibold">What it does</h2>
        <ul className="mt-4 space-y-2 text-sm">
          <li>🛡️ Floating shield on top of every app — drag it anywhere</li>
          <li>📝 Ctrl+Shift+S scans text you've selected in any app</li>
          <li>✂️ Ctrl+Shift+Q snips a QR code anywhere on your screen</li>
          <li>🔗 Links, SMS, Mail, QR camera/upload, UPI checks and a dashboard</li>
          <li>🔒 Runs on your computer — nothing is uploaded or opened</li>
        </ul>
        <button
          onClick={download}
          className="glow-primary mt-6 w-full rounded-xl bg-primary py-3 font-semibold text-primary-foreground"
        >
          ⬇ Download SafeScan AI for Windows
        </button>
      </div>
    </div>
  );
}
