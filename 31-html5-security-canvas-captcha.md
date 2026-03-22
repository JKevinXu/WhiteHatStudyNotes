# 31 - HTML5 Security: New XSS Vectors, Sandboxed Iframes, and Canvas-Based CAPTCHA Breaking

## HTML5 Introduced New XSS Vectors

### Video/Audio Event Handlers

```html
<video src="http://tinyvid.tv/file/29d6g90a204i1.ogg"
  onloadedmetadata="alert(document.cookie);"
  ondurationchanged="alert(/XSS2/);"
  ontimeupdate="alert(/XSS1/);"
  tabindex="0">
</video>
```

HTML5 media elements introduced new event handlers that execute JavaScript:

| Event | Fires when |
|-------|-----------|
| `onloadedmetadata` | Media metadata (duration, dimensions) is loaded |
| `ondurationchanged` | The duration attribute changes |
| `ontimeupdate` | The playback position changes |

These bypass XSS filters that only blacklist classic events like `onclick`, `onmouseover`, `onerror`. The media doesn't even need to play successfully — metadata loading alone can trigger execution.

## HTML5 Sandboxed Iframes

```html
<iframe sandbox="allow-same-origin allow-forms allow-scripts"
    src="http://maps.example.com/embedded.html">
</iframe>
```

The `sandbox` attribute restricts what the iframe can do:

| Token | Allows |
|-------|--------|
| *(no value)* | Maximum restrictions — no scripts, no forms, no popups, unique origin |
| `allow-same-origin` | Iframe keeps its real origin (can access cookies, storage) |
| `allow-forms` | Form submission allowed |
| `allow-scripts` | JavaScript execution allowed |
| `allow-popups` | `window.open()` and `target="_blank"` allowed |
| `allow-top-navigation` | Iframe can navigate the top-level page |

**Security note:** Combining `allow-same-origin` + `allow-scripts` is dangerous — the iframe's script can remove its own `sandbox` attribute via `document.frames[0].removeAttribute('sandbox')`, defeating the sandbox entirely.

## Noreferrer Link Attribute

```html
<a href="xxx" rel="noreferrer">test</a>
```

The `rel="noreferrer"` attribute tells the browser not to send the `Referer` header when following the link. This prevents CSRF token leakage from URLs (see note 27), but it's controlled by the **linking page**, not the target.

## HTML5 Canvas — Pixel-Level Image Manipulation

### Basic Canvas Usage

```html
<canvas id="myCanvas" width="200" height="100" style="border:1px solid #c3c3c3;">
Your browser does not support the canvas element.
</canvas>

<script>
var c = document.getElementById("myCanvas");
var cxt = c.getContext("2d");
cxt.fillStyle = "#FF0000";
cxt.fillRect(0, 0, 150, 75);
</script>
```

Canvas provides a JavaScript API for drawing and **reading pixel data** from images. This is significant for security because it enables client-side image analysis.

## Breaking CAPTCHAs with Canvas

Canvas can load a CAPTCHA image, read every pixel, and use image processing to recognize the characters — all in the browser, no server needed.

### Step 1: Convert to Greyscale

```javascript
function convert_grey(image_data) {
  for (var x = 0; x < image_data.width; x++) {
    for (var y = 0; y < image_data.height; y++) {
      var i = x * 4 + y * 4 * image_data.width;
      var luma = Math.floor(
        image_data.data[i]     * 299/1000 +   // Red
        image_data.data[i+1]   * 587/1000 +   // Green
        image_data.data[i+2]   * 114/1000      // Blue
      );
      image_data.data[i]   = luma;
      image_data.data[i+1] = luma;
      image_data.data[i+2] = luma;
      image_data.data[i+3] = 255;              // Full opacity
    }
  }
}
```

Each pixel in canvas `ImageData` is 4 bytes: `[R, G, B, A]`. The luma formula (BT.601 standard) converts color to perceived brightness, simplifying the image.

### Step 2: Filter by Color to Isolate Characters

```javascript
filter(image_data[0], 105);
filter(image_data[1], 120);
filter(image_data[2], 135);

function filter(image_data, colour) {
  for (var x = 0; x < image_data.width; x++) {
    for (var y = 0; y < image_data.height; y++) {
      var i = x * 4 + y * 4 * image_data.width;
      if (image_data.data[i] == colour) {
        // Target colour → white (keep)
        image_data.data[i]   = 255;
        image_data.data[i+1] = 255;
        image_data.data[i+2] = 255;
      } else {
        // Everything else → black (remove)
        image_data.data[i]   = 0;
        image_data.data[i+1] = 0;
        image_data.data[i+2] = 0;
      }
    }
  }
}
```

Each CAPTCHA character may use a different greyscale shade. By filtering for specific values (105, 120, 135), each character is isolated into a separate binary (black/white) image.

### Step 3: Remove Noise (Single-Pixel Lines)

```javascript
var i     = x * 4 + y * 4 * image_data.width;
var above = x * 4 + (y-1) * 4 * image_data.width;
var below = x * 4 + (y+1) * 4 * image_data.width;

if (image_data.data[i]     == 255 &&    // Current pixel is white
    image_data.data[above] == 0   &&    // Pixel above is black
    image_data.data[below] == 0)  {     // Pixel below is black
  // Isolated horizontal line — noise, remove it
  image_data.data[i]   = 0;
  image_data.data[i+1] = 0;
  image_data.data[i+2] = 0;
}
```

If a white pixel has black pixels above and below, it's a single-pixel-thick horizontal line — likely noise added by the CAPTCHA, not part of a character. Remove it.

### Step 4: Crop Individual Characters

```javascript
cropped_canvas.getContext("2d").fillRect(0, 0, 20, 25);
var edges = find_edges(image_data[i]);
cropped_canvas.getContext("2d").drawImage(
  canvas,
  edges[0], edges[1],                    // Source x, y
  edges[2]-edges[0], edges[3]-edges[1],  // Source width, height
  0, 0,                                  // Destination x, y
  edges[2]-edges[0], edges[3]-edges[1]   // Destination width, height
);
image_data[i] = cropped_canvas.getContext("2d").getImageData(
  0, 0, cropped_canvas.width, cropped_canvas.height
);
```

`find_edges()` scans the binary image to find the bounding box of the character (leftmost, topmost, rightmost, bottommost non-black pixel). The character is then cropped into a small canvas for comparison against known character templates.

### The Complete Pipeline

```
CAPTCHA image
  → Load into canvas
  → Convert to greyscale (luma)
  → Filter by shade to isolate each character
  → Remove noise (single-pixel lines)
  → Crop each character by bounding box
  → Compare against character templates
  → Output recognized text
```

### Security Implications

- **Same-origin restriction:** Canvas can only read pixels from same-origin images. Cross-origin images "taint" the canvas, and `getImageData()` throws a security error. This prevents using canvas to read CAPTCHA images from other domains.
- **But:** If the attacker has XSS on the target domain, or the CAPTCHA image allows cross-origin access (`Access-Control-Allow-Origin`), the canvas attack works.
- **Simple CAPTCHAs are broken:** Fixed-color characters with simple noise are trivially defeated. Modern CAPTCHAs use distortion, overlapping characters, and variable backgrounds to resist pixel-level analysis.
