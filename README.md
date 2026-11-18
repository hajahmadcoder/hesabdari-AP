# حسابداری AP (دفتر)
اپلیکیشن حسابداری فروشگاهی — بدهی/طلب مشتریان، دو ارز (افغانی/تومان)، حسابداری شخصی، اشتراک، ربات تلگرام.

| پوشه | محتوا | محل استقرار |
|---|---|---|
| `web/` | اپ وب (SPA) — منبع اصلی | Cloudflare Pages `hesabdariap.pages.dev` |
| `host-cpanel/` | صفحه‌ی معرفی + `/app/` (کپی اپ) | هاست `ap.coder-team.ir` |
| `android-sketchware/` | کدهای Java پروژه‌ی Sketchware (package `hesabdari.AP.com`) | Sketchware Pro |
| `worker/hesabdari-api.js` | بک‌اند یکپارچه (Worker + D1 `DB`) — همگام با نسخه‌ی دیپلوی‌شده | Cloudflare Workers `hesabdari-api` |
| `landing-github/` | صفحه‌ی معرفی ساده (دانلود APK) | — |
| `docs/HANDOFF.md` | یادداشت تحویل و کارهای باز | — |

هیچ توکن یا رمزی در این مخزن نگذارید؛ Secretها فقط در تنظیمات Worker.
