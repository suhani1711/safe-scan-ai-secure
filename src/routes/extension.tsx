import { createFileRoute } from "@tanstack/react-router";
import { PageHeader } from "@/components/PageHeader";

export const Route = createFileRoute("/extension")({
  head: () => ({
    meta: [
      { title: "SafeScan AI Shield — Chrome & Edge extension" },
      { name: "description", content: "Install the SafeScan AI Shield extension: a floating shield on every website in every browser window that checks links, messages, emails, QR codes and selected text." },
      { property: "og:title", content: "SafeScan AI Shield extension" },
      { property: "og:description", content: "Your AI shield against scams on every website, in every browser window." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: Ext,
});

function download() {
  fetch("/safescan-extension.zip")
    .then((r) => {
      if (!r.ok) throw new Error(`Download failed: ${r.status}`);
      return r.blob();
    })
    .then((b) => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(b);
      a.download = "safescan-extension.zip";
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
        title="SafeScan AI Shield extension"
        subtitle="A shield on every website, in every browser window, that checks what you're looking at before you trust it."
      />

      <div className="glass mt-8 rounded-2xl p-6">
        <h2 className="font-display text-xl font-semibold">What it does</h2>
        <ul className="mt-4 space-y-2 text-sm">
          <li>🛡️ Floating shield on every website, in every window — drag it anywhere</li>
          <li>⚡ Reload already-open tabs after installing to show the shield</li>
          <li>📝 Scan text you've selected on any page</li>
          <li>✂️ Snip a QR code on the screen, or use camera/upload</li>
          <li>🔗 Links, SMS, Mail and QR checks — turn the shield on or off from the toolbar</li>
          <li>🔒 Everything runs in your browser — nothing is sent anywhere</li>
        </ul>
        <button
          onClick={download}
          className="glow-primary mt-6 w-full rounded-xl bg-primary py-3 font-semibold text-primary-foreground"
        >
          ⬇ Download extension for Chrome / Edge
        </button>
      </div>

      <div className="glass mt-6 rounded-2xl p-6">
        <h2 className="font-display text-xl font-semibold">How to install</h2>
        <ol className="mt-4 list-decimal space-y-2 pl-5 text-sm">
          <li>Unzip the downloaded file.</li>
          <li>Open <b>chrome://extensions</b> (or <b>edge://extensions</b>).</li>
          <li>Turn on <b>Developer mode</b> (top-right).</li>
          <li>Click <b>Load unpacked</b> and choose the unzipped folder.</li>
          <li>Reload open website tabs. The shield appears bottom-right in your browser windows.</li>
        </ol>
      </div>
    </div>
  );
}
