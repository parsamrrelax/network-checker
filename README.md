# Network Checker

<p align="center">
  <strong>Set of network tools curated for Iran's Internet situation.</strong><br>
  مجموعه ابزارهای شبکه برای وضعیت اینترنت ایران
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Android%20%7C%20Windows%20%7C%20Linux-blue?style=flat-square" alt="Platform">
  <a href="https://github.com/mirarr-app/network-checker/releases">
    <img src="https://img.shields.io/github/v/release/mirarr-app/network-checker?style=flat-square&color=green" alt="Latest Release">
  </a>
</p>

---

## 📥 Download / دانلود

Available for Android, Windows, and Linux.  
برای اندروید، ویندوز و لینوکس در دسترس است.

<p align="left">
  <a href="https://github.com/mirarr-app/network-checker/releases">
    <img src="https://raw.githubusercontent.com/NeoApplications/Neo-Backup/034b226cea5c1b30eb4f6a6f313e4dadcbb0ece4/badge_github.png" width="180">
  </a>
</p>

---

## 📱 Screenshots / اسکرین‌شات‌ها

### Desktop
| Domain Checker | DNS Latency Test |
| :---: | :---: |
| ![Domain Checker](https://github.com/user-attachments/assets/cb49a96d-d86f-4041-b273-18b0568080a9) | ![DNS Latency Test](https://github.com/user-attachments/assets/0eb2a4af-bc10-44c5-9c77-da38b3e2751f) |
| **DNS Hunter** | **Edge IP Checker** |
| ![DNS Hunter](https://github.com/user-attachments/assets/b3e88496-bbe8-4250-91a4-999fc2f2d7e9) | ![Edge IP Checker](https://github.com/user-attachments/assets/5250f5b7-13f9-47d5-a9c3-24eb29e5b87b) |
| **Vless Config Modifier** | **CDN Xray Scanner** |
| ![Vless Config Modifier](https://github.com/user-attachments/assets/25c935e2-fe52-43b6-a245-a6daf1da83d5) | ![CDN Xray Scanner](https://github.com/user-attachments/assets/ee58ee80-c7ec-4d43-8548-5080480b0aa6) |

### Mobile
| Domain Checker | DNS Latency Test | DNS Hunter |
| :---: | :---: | :---: |
| ![Domain Checker](https://github.com/user-attachments/assets/e8c7edd0-cabe-49d7-b2d9-9d0ac5530606) | ![DNS Latency Test](https://github.com/user-attachments/assets/2c5f03d6-e3fb-4dbf-8523-9588dbbebf9c) | ![DNS Hunter](https://github.com/user-attachments/assets/1f9c5284-d174-4faa-ab3f-dc2af53939be) |
| **Edge IP Checker** | **Vless Config Modifier** | **Encode For SMS** |
| ![Edge IP Checker](https://github.com/user-attachments/assets/3f99b877-0403-40c2-b3ea-20fd710ca364) | ![Vless Config Modifier](https://github.com/user-attachments/assets/cafc79e5-6dd2-4451-ba0d-f0f2aaae4a12) | ![Encode For SMS](https://github.com/user-attachments/assets/0c1910ab-f7e0-441f-b2e5-906f685c788c) |

---

## ⚡ Features (English)

### Internet Diagnostics
A set of automated tests for different network protocols, DNS providers, websites accessibility and more. Ready to be analyzed with AI.

### Domain Checker
Scan most visited domains to check which ones are accessible. With the ability to add custom ones!

### DNS Latency Test
Latency test famous DNS providers. Inspired by [DNS-XS](https://github.com/code3-dev/DNS-XS)

### DNS Hunter
Test to check what Iranian datacenters resolve dns requests to specific domains. Inspired by [DNS Hunter](https://github.com/30niorcrypto/DNS-Hunter)

### Edge IP Checker
Scan for accessible Cloudflare Edge IPs. Inspired by [CF Scan Tolid Melli](https://github.com/AghaFarokh/CF-Scan-TolidMelli)

> 💡 **Linux Note:** If you're scanning a lot of IPs on Linux, run this command before launching the app (it will reset after a reboot):
> ```bash
> ulimit -S -c unlimited -d unlimited -f unlimited -i unlimited -l unlimited -m unlimited -n 65535 -q unlimited -s unlimited -t unlimited -u 65535 -v unlimited -x unlimited
> ```

### Vless Config Modifier
Replace the IP address in a vless config with other IPs from a list or IP ranges and get all the vless configs back. Inspired by [v2ray config modifier](https://github.com/seramo/v2ray-config-modifier)

### CDN Xray Scanner
Scan CDN IP ranges using Xray core and your own json config. Inspired by the GOAT, [Morteza Bashsiz Scanner](https://github.com/MortezaBashsiz/CFScanner).  
* In order to prepare your json configuration for scanning [read this guide](https://github.com/mirarr-app/network-checker/blob/main/get_json_for_cdn_scan.md).

### Netlify Config Generator
Generate multiple netlify configurations from multiple SNIs and IPs. Inspired by `IR_NETLIFY`.

### Akamai Scanner
Scan Akamai IP ranges.

### SNI Spoof Check
Check if SNI spoofing is open. Inspired by [sni scanner](https://github.com/seramo/sni-scanner)

### 🤖 Android-Only Features
* **Config Encoder for SMS:** Normally sending configs via SMS is blocked. This tool lets you encode English text using Persian characters and decode it on the target device.

---

## ⚡ ویژگی‌ها (فارسی)

### تست کامل شبکه
تحلیل کامل پروتکل‌ها، شبکه‌های اجتماعی، وبسایت‌های معروف، دی‌ان‌اس‌های معروف و موارد دیگر آماده شده برای تحلیل با هوش مصنوعی.

### بررسی‌کننده دامنه
اسکن پربازدیدترین دامنه‌ها برای بررسی در دسترس بودن آن‌ها. با قابلیت اضافه کردن دامنه‌های دلخواه.

### تست تأخیر DNS
تست تأخیر ارائه‌دهندگان معروف DNS. الهام گرفته از [DNS-XS](https://github.com/code3-dev/DNS-XS)

### DNS Hunter
تست برای بررسی اینکه دیتاسنترهای ایرانی درخواست‌های DNS چه دامنه‌هایی را resolve می‌کنند. الهام گرفته از [DNS Hunter](https://github.com/30niorcrypto/DNS-Hunter)

### بررسی‌کننده Edge IP
اسکن برای یافتن IP های Edge کلودفلر که در دسترس هستند. الهام گرفته از [CF Scan Tolid Melli](https://github.com/AghaFarokh/CF-Scan-TolidMelli)

> ℹ️ **توضیحات تکمیلی:**
> * با این اسکن می‌توانید آی‌پی تمیز کلودفلر پیدا کنید. رنج‌های رسمی کلودفلر با دکمه دیفالت بررسی می‌شوند.
> * تمام رنج‌هایی که می‌توانید اسکن کنید رنج‌های رسمی نیستند. هر رنج آی‌پی که از سرویس کلودفلر استفاده می‌کند قابل استفاده است (حتی رنج‌های ایرانی).
> * از تنظیمات بالای صفحه می‌توانید دامنه برای اتصال را عوض کنید. پیش‌فرض دامنه چت‌جی‌پی‌تی انتخاب شده ولی هر دامنه‌ای که پشت کلودفلر باشد قابل استفاده است.
> * برای ورسل نیز می‌توانید از اسکنر استفاده کنید؛ اما در حال حاضر فقط دامنه اصلی ورسل برای اسکن قابل استفاده است.

### ویرایشگر کانفیگ Vless
جایگزینی آدرس IP در کانفیگ vless با IP های دیگر از یک لیست یا بازه IP و دریافت تمام کانفیگ‌های vless. الهام گرفته از [v2ray config modifier](https://github.com/seramo/v2ray-config-modifier)

### اسکنر CDN Xray
اسکن بازه‌های IP سی‌دی‌ان با استفاده از هسته Xray و کانفیگ json شخصی شما. الهام گرفته از استاد، [Morteza Bashsiz Scanner](https://github.com/MortezaBashsiz/CFScanner)  
* برای گرفتن json از کانفیگ خود برای اسکن [اینجا را مطالعه کنید](https://github.com/mirarr-app/network-checker/blob/main/get_json_for_cdn_scan_fa.md).

> ℹ️ **توضیحات تکمیلی:**
> * با این اسکن می‌توانید آی‌پی تمیز برای هر سی‌دی‌انی پیدا کنید. این اسکنر از هسته xray برای تست آی‌پی‌ها استفاده می‌کند، پس در صورت موفقیت آمیز بودن تست، آی‌پی حتماً در کانفیگ شما کار خواهد کرد.
> * از تنظیمات ‌می‌توانید تعداد اسکن همزمان را افزایش دهید.

### کانفیگ Netlify
تولید چندین کانفیگ netlify از چندین SNI و IP. الهام گرفته از `IR_NETLIFY`

### اسکنر Akamai
اسکن بازه‌های IP Akamai

### چک کردن sni spoof
چک کردن باز بودن sni spoof. الهام گرفته شده از [sni scanner](https://github.com/seramo/sni-scanner)

### 🤖 ویژگی‌های مخصوص اندروید
* **رمزگذار کانفیگ برای پیامک:** معمولاً ارسال کانفیگ‌ها از طریق پیامک مسدود است. این ابزار به شما امکان می‌دهد متن انگلیسی را با کاراکترهای فارسی رمزگذاری کنید و در دستگاه دیگر رمزگشایی کنید.
