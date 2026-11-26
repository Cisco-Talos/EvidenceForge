const SVG_STYLE = [
  "color", "fill", "fill-opacity", "font-family", "font-size", "font-weight", "opacity",
  "paint-order", "rx", "stroke", "stroke-dasharray", "stroke-linecap", "stroke-linejoin",
  "stroke-opacity", "stroke-width", "visibility",
];

/** Copy an SVG with its computed styles inlined, so it renders the same outside the page. */
function styledCopy(viewport: SVGSVGElement, width: number, height: number, viewBox: string): SVGSVGElement {
  const copy = viewport.cloneNode(true) as SVGSVGElement;
  copy.setAttribute("width", String(width));
  copy.setAttribute("height", String(height));
  copy.setAttribute("viewBox", viewBox);
  const originals = viewport.querySelectorAll<SVGElement>("*");
  copy.querySelectorAll<SVGElement>("*").forEach((element, index) => {
    const rendered = getComputedStyle(originals[index]);
    SVG_STYLE.forEach((property) => element.style.setProperty(property, rendered.getPropertyValue(property)));
  });
  return copy;
}

async function rasterize(copy: SVGSVGElement, width: number, height: number, scale: number, backdrop: string): Promise<HTMLCanvasElement> {
  const image = new Image();
  await new Promise<void>((resolve, reject) => {
    image.onload = () => resolve();
    image.onerror = () => reject(new Error("The network map could not be captured"));
    image.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(new XMLSerializer().serializeToString(copy));
  });
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(width * scale));
  canvas.height = Math.max(1, Math.round(height * scale));
  const context = canvas.getContext("2d");
  if (!context) throw new Error("Image capture is unavailable");
  context.fillStyle = backdrop;
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  return canvas;
}

/** Export the rendered viewport, including its camera, theme and active layers. */
export async function captureNetworkView(viewport: SVGSVGElement): Promise<string> {
  const { width, height } = viewport.getBoundingClientRect();
  if (!width || !height) throw new Error("The network map is outside the visible window");
  const copy = styledCopy(viewport, width, height, `0 0 ${width} ${height}`);
  const backdrop = getComputedStyle(viewport.parentElement ?? viewport).backgroundColor;
  const canvas = await rasterize(copy, width, height, Math.min(2, 1400 / Math.max(width, height)), backdrop);
  const png = canvas.toDataURL("image/png");
  if (!png.startsWith("data:image/png;base64,") || png.length > 3_000_000) {
    throw new Error("The captured network view could not be attached");
  }
  return png;
}

/** Largest side, in pixels, of an exported diagram image. */
const EXPORT_LIMIT = 6000;

/**
 * Render exactly the map as shown, with its camera, collapsed sites, layers and selection, at a
 * higher resolution than the screen for saving or pasting.
 */
export async function captureViewImage(viewport: SVGSVGElement): Promise<Blob> {
  const { width, height } = viewport.getBoundingClientRect();
  if (!width || !height) throw new Error("The network map is outside the visible window");
  const copy = styledCopy(viewport, width, height, `0 0 ${width} ${height}`);
  const backdrop = getComputedStyle(viewport.parentElement ?? viewport).backgroundColor;
  const canvas = await rasterize(copy, width, height, Math.min(3, EXPORT_LIMIT / Math.max(width, height)), backdrop);
  return new Promise<Blob>((resolve, reject) => canvas.toBlob((blob) => blob ? resolve(blob) : reject(new Error("The diagram image could not be created")), "image/png"));
}

/** Put the map as shown on the clipboard as a PNG image. */
export async function copyViewImage(capture: () => Promise<Blob>): Promise<void> {
  if (typeof ClipboardItem === "undefined" || !navigator.clipboard?.write) {
    throw new Error("Copying images is not available here");
  }
  // Pass the pending image so the copy keeps the click's user activation in WebKit.
  const image = capture();
  // A clipboard implementation may reject before it consumes the image promise.
  void image.catch(() => undefined);
  await Promise.all([navigator.clipboard.write([new ClipboardItem({ "image/png": image })]), image]);
}
