const SVG_STYLE = [
  "color", "fill", "fill-opacity", "font-family", "font-size", "font-weight", "opacity",
  "paint-order", "rx", "stroke", "stroke-dasharray", "stroke-linecap", "stroke-linejoin",
  "stroke-opacity", "stroke-width", "visibility",
];

/** Export the rendered viewport, including its camera, theme and active layers. */
export async function captureNetworkView(viewport: SVGSVGElement): Promise<string> {
  const { width, height } = viewport.getBoundingClientRect();
  if (!width || !height) throw new Error("The network map is outside the visible window");

  const copy = viewport.cloneNode(true) as SVGSVGElement;
  copy.setAttribute("width", String(width));
  copy.setAttribute("height", String(height));
  copy.setAttribute("viewBox", `0 0 ${width} ${height}`);
  const originals = viewport.querySelectorAll<SVGElement>("*");
  copy.querySelectorAll<SVGElement>("*").forEach((element, index) => {
    const rendered = getComputedStyle(originals[index]);
    SVG_STYLE.forEach((property) => element.style.setProperty(property, rendered.getPropertyValue(property)));
  });
  const backdrop = getComputedStyle(viewport.parentElement ?? viewport).backgroundColor;
  const image = new Image();
  await new Promise<void>((resolve, reject) => {
    image.onload = () => resolve();
    image.onerror = () => reject(new Error("The network map could not be captured"));
    image.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(new XMLSerializer().serializeToString(copy));
  });
  const scale = Math.min(2, 1400 / Math.max(width, height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(width * scale));
  canvas.height = Math.max(1, Math.round(height * scale));
  const context = canvas.getContext("2d");
  if (!context) throw new Error("Image capture is unavailable");
  context.fillStyle = backdrop;
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.drawImage(image, 0, 0, canvas.width, canvas.height);
  const png = canvas.toDataURL("image/png");
  if (!png.startsWith("data:image/png;base64,") || png.length > 3_000_000) {
    throw new Error("The captured network view could not be attached");
  }
  return png;
}
