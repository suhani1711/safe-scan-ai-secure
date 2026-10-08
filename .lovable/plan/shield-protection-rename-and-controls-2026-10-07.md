# Shield Protection rename and controls

## Changes
- Rename the `/extension` page to `/shield-protection` and update every navigation and homepage link to use “Shield Protection.”
- Replace the existing download-focused page with the requested description, an accessible on/off switch, status text, and an “Open scanner” button.
- Initialize and continuously synchronize the switch from `localStorage["safescan:v1"]`; enable with a bounded widget-ready retry and disable immediately through the existing widget API.
- Remove obsolete desktop/extension downloads, source files, and stale references while preserving `public/safescan-widget.js` and its root script tag.
- Update project documentation that still describes the removed extension download.

## Technical details
- Define the widget API type locally without changing the widget file.
- Poll state every 500 ms with cleanup on unmount; retry enablement every 200 ms for at most 5 seconds.
- Use the existing design-system button for “Open scanner” and a semantic switch control for protection state.
- Verify the renamed route, widget interactions, responsive layout, and current build output.
