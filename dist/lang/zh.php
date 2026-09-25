<?php
/* Перевод сайта: [английская строка => перевод]. Основной язык — английский. */
return [
    'Guide' => '使用指南',
    'App' => '应用',
    'Install the app' => '安装应用',
    'Accept' => '接受',
    'Time' => '时间',
    'Security' => '安全',
    '. The' => '。',
    'Open' => '打开',
    'and' => '与',
    'QR code' => '二维码',
    'Link' => '链接',
    'Text' => '文本',
    'OR' => '或',
    'AND' => '且',
    'The' => '网站上的',
    'Copy' => '复制',
    'Access request — Entrixy' => '访问请求 — Entrixy',
    'A service is asking for access to your barrier. Decide yourself what to grant and take it back at any time.' => '某项服务请求进入您的道闸。给什么由您决定，随时可以收回。',
    'Access to your barrier' => '进入您的道闸',
    'You decide what to grant, see every opening in the log and take access back in one tap.' => '给什么由您决定，每次开启都记入日志，收回权限只需一点。',
    'This company is asking for access to your barrier so that its employee can drive in on the day of the visit. Access is granted to the company, not to a particular person, and every opening is recorded in your log with the name of whoever pressed the button.' => '这家公司请求进入您的道闸，以便其员工在上门当天驶入。权限给的是公司而非某个人，每次开启都会记入您的日志并注明是谁按的。',
    'Install the app and add your barrier — it takes a couple of minutes.' => '安装应用并添加您的道闸——只要几分钟。',
    'Grant access: the company will already be waiting in the list, nothing to copy or forward.' => '授予权限：这家公司已经在列表里等着，无需复制或转发任何东西。',
    'Take it back whenever you want. The company cannot pass the access on to anyone else.' => '随时可以收回。这家公司无法把权限再转给别人。',
    'Your barrier has to open on a call from your number, and your phone has to stay online — the app dials for you at the moment of the request. If your barrier has an Entrixy controller, the phone is not needed at all.' => '您的道闸需要能用您的号码打电话开启，且手机保持在线——请求发生时由应用替您拨号。若道闸装了 Entrixy 控制器，则完全不需要手机。',
    'This request has expired. Ask the company for a new link — it takes them one click.' => '该请求已过期。向公司要一个新链接即可，对他们只是一次点击。',
    'This link is not valid. Check that the address was scanned in full, or ask the company for a new one.' => '此链接无效。请确认地址是否完整扫描，或向公司索取新的链接。',
    'State' => '状态',
    'Logo' => '标志',
    'domain not confirmed' => '域名未确认',
    'Android app' => 'Android 应用',
    'guide' => '指南',
    '.
        Do you manufacture hardware?' => '。
        您是硬件制造商吗？',
    'app' => '应用',
    'server' => '服务器',
    'to your' => '到您的',
    'Compute' => '计算',
    'POST &lt;your webhook_url&gt;
Content-Type: application/json

{
  "action":    "open",
  "object_id": 42,
  "timestamp": 1750000000,
  "nonce":     "0011223344556677",
  "signature": "9d7b58066094fa88..."
}' => 'POST &lt;your webhook_url&gt;
Content-Type: application/json

{
  "action":    "open",
  "object_id": 42,
  "timestamp": 1750000000,
  "nonce":     "0011223344556677",
  "signature": "9d7b58066094fa88..."
}',
    'objects' => '个对象',
    'Open in the app' => '在应用中打开',
    'with its own' => '用它自己的',
    'Code' => '代码',
    'offset  size  field
[0..1]   2    Company ID = E0 00
[2..5]   4    device_id            (LE)
[6..9]   4    counter              (LE, monotonic, anti-replay, survives deep sleep)
[10..17] 8    auth_hmac            = HMAC(owner_secret, mac_in)[0..7]
[18]     1    sleep_interval_s     (plaintext)
[19..22] 4    opts_cipher          (battery, status, fw, hw — encrypted)' => 'offset  size  field
[0..1]   2    Company ID = E0 00
[2..5]   4    device_id            (LE)
[6..9]   4    counter              (LE, monotonic, anti-replay, survives deep sleep)
[10..17] 8    auth_hmac            = HMAC(owner_secret, mac_in)[0..7]
[18]     1    sleep_interval_s     (plaintext)
[19..22] 4    opts_cipher          (battery, status, fw, hw — encrypted)',
    'K_state = HKDF-SHA256(salt=null, ikm=owner_secret, info="ble-state-v1", L=16)
[..21] state_enc = state_byte XOR K_state[counter &amp; 15]     // bit0: 1=open, 0=closed
[22..23] state_mac = HMAC-SHA256(K_state, counter(4B LE) || state_enc)[0..1]   // 2 bytes' => 'K_state = HKDF-SHA256(salt=null, ikm=owner_secret, info="ble-state-v1", L=16)
[..21] state_enc = state_byte XOR K_state[counter &amp; 15]     // bit0: 1=open, 0=closed
[22..23] state_mac = HMAC-SHA256(K_state, counter(4B LE) || state_enc)[0..1]   // 2 bytes',
    'The server' => '服务器',
    'without' => '（不带',
    'with' => '，带',
    'every' => '），每隔',
    'With' => '使用',
    'instead of' => '而不是',
    'Check' => '校验',
    'empty' => '空',
    'Guest' => '访客',
    '→ device_hello
{ "type":"device_hello",
  "device_key":    "&lt;32 hex&gt;",
  "device_secret": "&lt;32 hex&gt;",
  "e2ee":          true|false }        // whether a valid ownerSecret exists (§5)' => '→ device_hello
{ "type":"device_hello",
  "device_key":    "&lt;32 hex&gt;",
  "device_secret": "&lt;32 hex&gt;",
  "e2ee":          true|false }        // whether a valid ownerSecret exists (§5)',
    '❮&nbsp; device_ok  { "type":"device_ok", "hb_interval":300 }   // success; hb_interval in s (10..3600)
← error      { "type":"error", "reason":"auth" }         // failure → the server closes' => '❮&nbsp; device_ok  { "type":"device_ok", "hb_interval":300 }   // success; hb_interval in s (10..3600)
← error      { "type":"error", "reason":"auth" }         // failure → the server closes',
    '❮&nbsp; device_command
{ "type":"device_command", "action":"open", "command_id":"&lt;id&gt;", "number_id":&lt;n&gt; }
  // action:"close" — for a bistable drive' => '❮&nbsp; device_command
{ "type":"device_command", "action":"open", "command_id":"&lt;id&gt;", "number_id":&lt;n&gt; }
  // action:"close" — for a bistable drive',
    'PROVISION &lt;64 hex&gt;   → store the ownerSecret in NVS, return the fingerprint
WIPE                  → erase it (basic mode)
STATUS                → show the fingerprint
fingerprint = HMAC-SHA256(ownerSecret, "fp")[0..3]  (hex)' => 'PROVISION &lt;64 hex&gt;   → store the ownerSecret in NVS, return the fingerprint
WIPE                  → erase it (basic mode)
STATUS                → show the fingerprint
fingerprint = HMAC-SHA256(ownerSecret, "fp")[0..3]  (hex)',
    'token (3B) = [guest_did 2B LE][perms 1B]                      // a capability, no TTL
owner_sig  = HMAC-SHA256(ownerSecret, token)[0..15]
guest_key  = HKDF-SHA256(salt=null, ikm=ownerSecret, info="guest"||guest_did(2B LE), L=32)
proof      = HMAC-SHA256(guest_key, nonce)[0..15]' => 'token (3B) = [guest_did 2B LE][perms 1B]                      // a capability, no TTL
owner_sig  = HMAC-SHA256(ownerSecret, token)[0..15]
guest_key  = HKDF-SHA256(salt=null, ikm=ownerSecret, info="guest"||guest_did(2B LE), L=32)
proof      = HMAC-SHA256(guest_key, nonce)[0..15]',
    'OK' => '好',
    'On' => '开',
    'Off' => '关',
    'or' => '或',
    'Bistable mode: the controller remembers the current position (open or closed) and
toggles it on every activation. The position is visible on the object icon in the app,
to owner and guest alike. The pin for the Close command is set below, in the Pins section.' => '双稳态模式：控制器会记住当前位置（已开或已关），
每次动作时切换一次。该位置会显示在应用的对象图标上，
所有者和访客都看得到。「关」指令所用的引脚在下面的「引脚」一节设置。',
    'Language' => '语言',
    'Config' => '配置',
    'or the' => '或',
    'Name' => '名称',
    'Type' => '类型',
    'Access' => '权限',
    'Everyone' => '所有人',
    'active' => '已激活',
    '<div class="pm-row"><b>A 30 A relay is on the board</b>, controlled from <code>GPIO16</code>. <code>NO</code>+<code>COM</code> go to the Open terminals.</div>
           <div class="pm-row"><b>Power</b>: straight from the <b>mains</b> to the AC terminals — the power supply is built into the board.</div>
           <div class="pm-row"><b>Uploading the program</b>: a USB-UART programmer on the <code>TX/RX/GND</code> pins. <b>Flash the board DISCONNECTED from the mains</b> — powered from the programmer only.</div>' => '<div class="pm-row"><b>板上有一个 30 A 继电器</b>，由 <code>GPIO16</code> 控制。<code>NO</code>+<code>COM</code> 接到 Open 端子。</div>
           <div class="pm-row"><b>供电</b>：直接从<b>市电</b>接到 AC 端子——电源模块已做在板上。</div>
           <div class="pm-row"><b>程序上传</b>：USB-UART 编程器接到 <code>TX/RX/GND</code> 引脚。<b>烧录时必须让板子脱离市电</b>——只由编程器供电。</div>',
    '<div class="pm-row"><b>The relay control input</b> → <code>GPIO26</code>. The dry contact <code>O</code>/<code>I</code> on the terminals goes to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V or DC 24–240 V to the terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: there is no external USB. Open the case and connect a USB-UART adapter to the ESP32\'s UART pads (<code>3V3, GND, TX, RX</code>; <code>IO0</code> to ground to enter the bootloader). The case must be <b>disconnected from the mains</b>.</div>' => '<div class="pm-row"><b>继电器控制输入</b> → <code>GPIO26</code>。端子上的干接点 <code>O</code>/<code>I</code> 接到「开」。</div>
           <div class="pm-row"><b>供电</b>：端子上接 AC 110–240 V 或 DC 24–240 V。</div>
           <div class="pm-row"><b>程序上传</b>：没有对外的 USB。打开外壳，用 USB-UART 适配器接到 ESP32 的 UART 焊盘（<code>3V3, GND, TX, RX</code>；把 <code>IO0</code> 接地以进入引导加载模式）。外壳必须<b>脱离市电</b>。</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB and a converter on it — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>继电器控制输入</b> → 引脚 <code>GPIO16</code>（可在下面的表单里更改）。</div>
           <div class="pm-row"><b>供电</b>：通过 USB 供 5 V，或接到 <code>5V</code>/<code>VIN</code> 引脚。继电器模块用它自己的 <code>VCC</code>。</div>
           <div class="pm-row"><b>程序上传</b>：板上带 USB 和转换芯片——程序<b>直接从浏览器</b>上传，不需要编程器。</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO16</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V to <code>5V</code> or 3.3 V to <code>3V3</code>, soldered. The relay module takes its own <code>VCC</code>.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module has no USB — drop it into a programmer and upload through the programmer\'s micro-USB. Only power and the relay are soldered to the module itself (do not forget the common ground, GND).</div>' => '<div class="pm-row"><b>继电器控制输入</b> → 引脚 <code>GPIO16</code>（可在下面的表单里更改）。</div>
           <div class="pm-row"><b>供电</b>：把 5 V 接到 <code>5V</code>，或把 3.3 V 接到 <code>3V3</code>，都靠焊接。继电器模块用它自己的 <code>VCC</code>。</div>
           <div class="pm-row"><b>程序上传</b>：裸模块没有 USB——把它插进编程器，通过编程器的 micro-USB 上传程序。模块本身只焊电源和继电器（别忘了共地 GND）。</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO3</code> (you can change it in the form).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB-C or 3.3 V to the <code>3V3</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: the board has USB-C — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>继电器控制输入</b> → 引脚 <code>GPIO3</code>（可在表单里更改）。</div>
           <div class="pm-row"><b>供电</b>：通过 USB-C 供 5 V，或把 3.3 V 接到 <code>3V3</code> 引脚。</div>
           <div class="pm-row"><b>程序上传</b>：板上带 USB-C——程序<b>直接从浏览器</b>上传，不需要编程器。</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V / 3.3 V, soldered to the module\'s pins.</div>
           <div class="pm-row"><b>Uploading the program</b>: a bare module goes into a programmer — you do not solder USB to it. Power and the relay are soldered.</div>' => '<div class="pm-row"><b>继电器控制输入</b> → 引脚 <code>GPIO4</code>（可在下面的表单里更改）。</div>
           <div class="pm-row"><b>供电</b>：5 V / 3.3 V，焊到模块的引脚上。</div>
           <div class="pm-row"><b>程序上传</b>：裸模块要插进编程器，不给它焊 USB。电源和继电器靠焊接。</div>',
    '<div class="pm-row"><b>The relay control input</b> → pin <code>GPIO4</code> (you can change it in the form below).</div>
           <div class="pm-row"><b>Power</b>: 5 V over USB or to the <code>5V</code>/<code>VIN</code> pin.</div>
           <div class="pm-row"><b>Uploading the program</b>: USB is on board — the program uploads <b>straight from the browser</b>, no programmer needed.</div>' => '<div class="pm-row"><b>继电器控制输入</b> → 引脚 <code>GPIO4</code>（可在下面的表单里更改）。</div>
           <div class="pm-row"><b>供电</b>：通过 USB 供 5 V，或接到 <code>5V</code>/<code>VIN</code> 引脚。</div>
           <div class="pm-row"><b>程序上传</b>：板载 USB——程序<b>直接从浏览器</b>上传，不需要编程器。</div>',
    '<div class="pm-row"><b>The relay is already on the board</b>, controlled from <code>GPIO16</code>. Its <code>NO</code>+<code>COM</code> output goes to the drive\'s Open terminals.</div>
           <div class="pm-row"><b>Power</b>: 5 V over micro-USB, or 7–30 V to the power terminals.</div>
           <div class="pm-row"><b>Uploading the program</b>: micro-USB here is power only (there is no UART) — hook a USB-UART programmer to the <code>TX/RX/GND</code> pins and pull <code>IO0</code> to ground as you power it up.</div>' => '<div class="pm-row"><b>继电器已在板上</b>，由 <code>GPIO16</code> 控制。<code>NO</code>+<code>COM</code> 输出接到驱动装置的 Open 端子。</div>
           <div class="pm-row"><b>供电</b>：通过 micro-USB 供 5 V，或在电源端子上接 7–30 V。</div>
           <div class="pm-row"><b>程序上传</b>：这里的 micro-USB 只供电（没有 UART）——把 USB-UART 编程器接到 <code>TX/RX/GND</code> 引脚，上电瞬间把 <code>IO0</code> 接地。</div>',
    '<div class="pm-row">The pinout and flashing are the same as on the Plus 1: relay <code>GPIO26</code>, dry contact <code>O</code>/<code>I</code> to Open.</div>
           <div class="pm-row"><b>Power</b>: AC 110–240 V.</div>
           <div class="pm-row"><b>Uploading the program</b>: open the case, USB-UART to the ESP32\'s UART pads (<code>3V3/GND/TX/RX</code>, <code>IO0</code> to ground). The power-metering chip is unused by the Entrixy firmware. Disconnect it from the mains.</div>' => '<div class="pm-row">引脚和烧录方式与 Plus 1 相同：继电器 <code>GPIO26</code>，干接点 <code>O</code>/<code>I</code> 接「开」。</div>
           <div class="pm-row"><b>供电</b>：AC 110–240 V。</div>
           <div class="pm-row"><b>程序上传</b>：打开外壳，USB-UART 接到 ESP32 的 UART 焊盘（<code>3V3/GND/TX/RX</code>，<code>IO0</code> 接地）。Entrixy 固件不使用功率测量芯片。请脱离市电。</div>',
    'account' => '我的账户',
    'Two bytes of tag are deliberate: the state byte only drives the open/closed indicator
and grants no authority, while every extra byte of advertisement costs battery on every
wake-up. The tag guards against corruption on the air, not against a forger — 16 bits
fall to brute force in seconds. Nothing that decides access may travel this way.' => '两个字节的标签是有意为之：状态字节只驱动“开/关”指示，不授予任何权限，而广播每多一个字节，都要在每次唤醒时消耗电量。该标签防的是空口上的损坏，不是伪造者——16 位几秒即可穷举。凡是决定访问权限的东西，都不该走这条路。',
    'Domain' => '域名',
    'expired' => '已过期',
    'This link has already been used: access for this visit is granted. If it was you, the company is in your app under companies, together with the log of openings — you take the access back there at any time. If the link reached you by chance, ask the company for a new one: each link works once.' => '这个链接已经用过：本次上门的权限已经授予。如果是你本人，公司就在你的应用"公司"标签页里，连同开门日志，随时可以在那里收回权限。如果链接是偶然到你手里的，请向公司索取新的：每个链接只能用一次。',
    'Copy the link' => '复制链接',
    'Be sure to check the domain %s against the site of the company you are about to grant access to.' => '务必把域名 %s 与你准备授予权限的那家公司的网站核对一致。',
    'This company has not confirmed a domain — there is only the name it entered. Grant access if you are sure who is asking.' => '这家公司没有确认域名——只有填写的名称。确定是谁在申请，再授予权限。',
    'The link is copied: after installation the app will pick it up itself, scanning again is not needed.' => '链接已复制：安装后应用会自己读取，无需再扫一次码。',
    'Powered by Entrixy' => '由 Entrixy 提供支持',
];
