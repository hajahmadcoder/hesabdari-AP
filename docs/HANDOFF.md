# دفتر | حسابداری AP — فایل تحویل برای ادامه‌ی کار

> این فایل را (یا کل زیپ را) در ابتدای گفتگوی بعدی آپلود کن تا بدون توضیح دوباره ادامه بدهیم.

## ۱) پروژه چیست
اپ حسابداری برای فروشگاه‌داران افغان: بدهی/طلب مشتریان، «فروشگاه مشتری»، حسابداری شخصی، اشتراک/پلن، ربات تلگرام، پنل مدیریت.
پشتیبانی داخل اپ: تلگرام @leader_arvah — کانال t.me/hesabdari_AP — سایت coder-b0l.pages.dev

## ۲) معماری (وضعیت فعلی)
- **فرانت:** یک فایل HTML (SPA)، دو نسخه‌ی یکسان:
  - **Cloudflare Pages** `https://hesabdariap.pages.dev/` (اپ در ریشه) ← اپ اندروید و مشتریان خارج از ایران. متای `noindex`.
  - **هاست سی‌پنل** `ap.coder-team.ir`: ریشه = صفحه‌ی معرفی (برای ایندکس گوگل)، `/app/` = خود اپ. (هاست: coder-team.ir، پوشه‌ی `ap_site`)
  - هر دو نسخه باید همیشه با همان ورکرها کار کنند.
- **بک‌اند:** Cloudflare Workers + دیتابیس D1 (binding با نام `DB`):
  `hesabdari-auth`، `hesabdari-data`، `hesabdari-personal` (ورود با **توکن Bearer** در localStorage) و `hesabdari-panel` (فقط ادمین، کوکی `psid`).
  `hesabdari-js` قدیمی و کوکی‌محور است — **استفاده نمی‌شود، دستش نزن.**
  ورکر یکپارچه (`4-worker`) ساخته شده؛ **دیپلوی/تستش تأیید نشده.**
- **CORS:** ورکرها Origin را بازتاب می‌دهند، پس هر دامنه‌ای کار می‌کند.
- **اثر انگشت وب (WebAuthn):** هر دامنه اعتبارنامه‌ی جدا دارد. ورکر یکپارچه هر دو دامنه را قبول می‌کند؛ `hesabdari-auth` فعلی یک `RP_ID` ثابت دارد.
- **اندروید:** Sketchware Pro، پروژه‌ی 1022، package = `hesabdari.AP.com`، WebView با `mainUrl = https://hesabdariap.pages.dev/`.
- **APK:** ریلیز گیت‌هاب `hajahmadcoder/hesabdari-AP` (لینک دانلود در صفحه‌ی معرفی به همین اشاره می‌کند).

## ۳) محتویات زیپ و محل نصب
| پوشه | کجا بگذار |
|---|---|
| `1-host-cpanel/` | همه را در پوشه‌ی زیردامنه (`ap_site`) سی‌پنل Extract کن. اگر `.htaccess` دیده نشد: File Manager → Settings → Show Hidden Files |
| `2-cloudflare-pages/` | در پروژه‌ی Pages به نام hesabdariap آپلود کن (Direct Upload). یا در Termux: `npx wrangler pages deploy . --project-name hesabdariap` |
| `3-android-sketchware/DaftarNotifier.java` و `DaftarNotifyJob.java` | Java/Kotlin Manager ← Java Class (package از قبل `hesabdari.AP.com` است) |
| `3-android-sketchware/daftar-app-main.java` | بلوک onCreate ← Add Source Directly (کل کد قبلی را جایگزین کن) |
| `3-android-sketchware/onBackPressed.java` | تب Event ← onBackPressed ← Add Source Directly |
| `4-worker/hesabdari-worker-merged.js` | ورکر جدید (مثلاً `hesabdari-core`) — مراحل پایین |

مانیفست (AndroidManifest Manager): مجوزهای `POST_NOTIFICATIONS`، `RECEIVE_BOOT_COMPLETED`، `INTERNET`، `USE_FINGERPRINT` + در App Components:
`<service android:name="hesabdari.AP.com.DaftarNotifyJob" android:permission="android.permission.BIND_JOB_SERVICE" android:exported="false"/>`

## ۴) آنچه در این نسخه هست
**اندروید:** قفل اپ (پین نمک‌دار + اثر انگشت) با آیکون واقعی، بازیابی با رمز حساب، زمان قفل مجدد و غیرفعال‌سازی موقت، اعلان‌ها (بدهی/واریزی، عضویت، پیام مدیریت، پایان اشتراک) هر ~۱۵ دقیقه و اجباری (دیالوگ مجوز با هر بار باز کردن اپ تا فعال شود)، دکمه‌ی برگشت قدم‌به‌قدم + دیالوگ خروج با طراحی خود اپ.
**وب:** تقویم شمسی/میلادی، مبلغ به حروف (تومان/افغانی)، حس اپ (بدون انتخاب متن)، پشته‌ی تاریخچه برای برگشت، «فراموشی پین» در قفل حساب، بخش پشتیبانی، فونت و jsPDF روی همان هاست (بدون گوگل/cdnjs)، بوت موازی برای سرعت.

## ۵) کارهای باز (پیشنهاد ترتیب)
1. **ورکر یکپارچه:** دیپلوی روی ورکر جدید + تست، بعد عوض‌کردن `AUTH_BASE/DATA_BASE/PERSONAL_BASE` در **هر دو** نسخه‌ی `index.html` (و خطوط `preconnect`)، ثابت‌های `DATA`/`AUTH` در `DaftarNotifier.java`، وبهوک تلگرام و آدرس API پنل مدیریت. ورکرهای قدیمی را تا چند روز نگه دار.
2. **پنل مدیریت:** فایل HTML پنل را من ندارم — بفرست تا برای هاست آماده و در زیپ بگذارم.
3. **لوگو:** هنوز نفرستاده‌ای؛ جایگزین مربع متنی «AP» در صفحه‌ی معرفی می‌شود.
4. **امضای APK برای بازار:** خطای «Keystore not found» در Sketchware حل نشده (پارک شده).
5. **APK گیت‌هاب:** مطمئن شو آخرین APK امضاشده در ریلیز آپلود است.
6. **سرعت روی ایران:** تست `.../api/me` روی workers.dev از ایران؛ روش اتصال ورکر «خراسان دیجیتال» (که سریع است) را مقایسه کن؛ احتمالاً Cloudflare جلوی دامنه.
7. **گوگل:** در Search Console برای `https://ap.coder-team.ir/` دوباره Request Indexing بزن (صفحه‌ی معرفی جای فرم ورود آمده).
8. **اختیاری:** لینک «نسخه‌ی جایگزین» (pages.dev) در صفحه‌ی معرفی برای خارج از ایران؛ جایگزینی `<select>` ها با انتخابگر سفارشی؛ ربات تلگرام: «درخواست کالا» هنوز «به‌زودی» است.
9. **نصب‌شده؟** معلوم نیست آخرین نسخه‌ی اندروید (onBackPressed، exitApp، بازیابی پین) بیلد و تست شده — اول تست کن.

## ۵.۱) دیپلوی ورکر یکپارچه
1. ورکر جدید بساز، محتوای `hesabdari-worker-merged.js` را بگذار.
2. Binding دیتابیس D1 با نام `DB` (همان دیتابیس قبلی).
3. متغیرها/Secretها (اسم‌ها): `TELEGRAM_BOT_TOKEN`، `OWNER_TELEGRAM_ID`، `SUPER_ADMIN_TELEGRAM_ID`، `WEBAPP_URL`، `TELEGRAM_WEBHOOK_SECRET`، `TELEGRAM_BOT_USERNAME`، `ADMIN_PANEL_URL` — مقدارها را از ورکرهای فعلی کپی کن (اینجا ننوشته‌ام).
4. Cron Trigger روزانه (یادآوری سررسید).
5. تست `/api/me` (باید `{"user":null}` بدهد)، بعد مراحل بند ۵-۱.

## ۶) نکات و دام‌ها
- خطای «DaftarNotifier cannot be resolved» = اختلاف package؛ راه‌حل: package درست + Clean temporary files.
- ورود با توکن Bearer است، نه کوکی (جز پنل مدیریت). مسیر `/auth/login` پاسخ `{token}` می‌دهد و اپ اندروید برای بازیابی پین و اعلان‌ها به آن وابسته است.
- هیچ توکن/رمزی را در چت نفرست. (قبلاً فایل خلاصه‌ای با توکن ربات و Cloudflare در چت رفته بود — اگر هنوز عوض نکرده‌ای: `/revoke` در BotFather و ساخت توکن‌های جدید.)
- دو نسخه‌ی `index.html` فقط در متای SEO فرق دارند (هاست: canonical؛ Pages: noindex). منبع اصلی همان نسخه‌ی Pages است.

## ۷) وضعیت بررسی‌شده (۱۸ نوامبر ۲۰۲۶)
- ورکر `hesabdari-api` روی Cloudflare **دیپلوی شده** (ساخت ۸ نوامبر، آخرین تغییر ۹ نوامبر) و از نسخه‌ی زیپ جدیدتر است: چندارزی (USD/PKR/TRY)، نرخ ارز فروشگاه (`store_rates`)، سطل زباله (`trash`)، `pin_len`، `ref_code`، CORS با credentials برای دامنه‌های معتبر. کد آن در `worker/hesabdari-api.js` است.
- دیتابیس `hesabdari-db` مایگریت شده (جدول‌های `store_rates` و `trash` و ستون‌های جدید وجود دارند) — ۱۶ کاربر، آخرین تراکنش ۱ نوامبر.
- اما `web/index.html` و `DaftarNotifier.java` در این مخزن هنوز به ورکرهای قدیمی (`hesabdari-auth/data/personal`) وصل‌اند و امکانات چندارزی را ندارند → احتمالاً نسخه‌ی جدیدتر فرانت جای دیگری است.
