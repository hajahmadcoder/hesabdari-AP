// ============================================================
// دفتر — موتور اعلان‌های اپ اندروید (بدون Firebase)
// در Sketchware Pro: Java/Kotlin Manager → Add class → اسمش: DaftarNotifier
// ⚠️ خط package باید دقیقاً با package اپ تو یکی باشه
// ============================================================
package hesabdari.AP.com;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

public class DaftarNotifier {

    static final String PREFS = "daftar_notify";
    static final String DATA = "https://hesabdari-api.haj-ahmad-coder.workers.dev/api";
    static final String AUTH = "https://hesabdari-api.haj-ahmad-coder.workers.dev/api";
    static final int JOB_ID = 1701;
    static final int SEEN_MAX = 500;

    static final String CH_TX = "daftar_tx";
    static final String CH_REQ = "daftar_req";
    static final String CH_SYS = "daftar_sys";

    private static final Object LOCK = new Object();

    // ---------------- session / settings ----------------
    static SharedPreferences sp(Context c) {
        return c.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public static void saveSession(Context c, String token) {
        if (token == null || token.length() < 8) return;
        sp(c).edit().putString("token", token).apply();
    }

    // اگه کاربر عوض شد، حافظه‌ی «دیده‌شده‌ها» ریست می‌شه تا اعلان قدیمی نریزه
    public static void setUser(Context c, String uid) {
        if (uid == null || uid.length() == 0) return;
        SharedPreferences p = sp(c);
        if (!uid.equals(p.getString("uid", ""))) {
            p.edit().putString("uid", uid).remove("seen").putBoolean("init", false).apply();
        }
    }

    public static void clearSession(Context c) {
        sp(c).edit().remove("token").remove("uid").remove("seen").putBoolean("init", false).apply();
        cancel(c);
    }

    public static boolean flag(Context c, String key) {
        return sp(c).getBoolean("n_" + key, true);
    }

    public static void setFlag(Context c, String key, boolean v) {
        sp(c).edit().putBoolean("n_" + key, v).apply();
    }

    // ---------------- scheduling ----------------
    public static void schedule(Context c) {
        try {
            if (Build.VERSION.SDK_INT < 21) return;
            JobScheduler js = (JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
            if (js == null) return;
            if (Build.VERSION.SDK_INT >= 24 && js.getPendingJob(JOB_ID) != null) return;
            ComponentName cn = new ComponentName(c, DaftarNotifyJob.class);
            JobInfo.Builder b = new JobInfo.Builder(JOB_ID, cn)
                    .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                    .setPeriodic(15 * 60 * 1000L);
            try {
                js.schedule(b.setPersisted(true).build());
            } catch (Exception e) {
                js.schedule(b.setPersisted(false).build());
            }
        } catch (Exception ignored) {}
    }

    public static void cancel(Context c) {
        try {
            if (Build.VERSION.SDK_INT >= 21) {
                JobScheduler js = (JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
                if (js != null) js.cancel(JOB_ID);
            }
        } catch (Exception ignored) {}
    }

    // ---------------- channels ----------------
    public static void ensureChannels(Context c) {
        if (Build.VERSION.SDK_INT < 26) return;
        NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm == null) return;
        nm.createNotificationChannel(new NotificationChannel(CH_TX, "بدهی و واریزی", NotificationManager.IMPORTANCE_HIGH));
        nm.createNotificationChannel(new NotificationChannel(CH_REQ, "درخواست‌ها", NotificationManager.IMPORTANCE_DEFAULT));
        nm.createNotificationChannel(new NotificationChannel(CH_SYS, "پیام‌های سیستم و اشتراک", NotificationManager.IMPORTANCE_DEFAULT));
    }

    public static boolean canNotify(Context c) {
        NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
        return nm != null && nm.areNotificationsEnabled();
    }

    public static void show(Context c, int id, String channel, String title, String text, String openTarget) {
        try {
            ensureChannels(c);
            Intent it = c.getPackageManager().getLaunchIntentForPackage(c.getPackageName());
            if (it == null) return;
            it.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            it.putExtra("daftar_open", openTarget == null ? "notifications" : openTarget);
            int fl = PendingIntent.FLAG_UPDATE_CURRENT | (Build.VERSION.SDK_INT >= 23 ? PendingIntent.FLAG_IMMUTABLE : 0);
            PendingIntent pi = PendingIntent.getActivity(c, id, it, fl);

            Notification.Builder nb = Build.VERSION.SDK_INT >= 26
                    ? new Notification.Builder(c, channel)
                    : new Notification.Builder(c);
            nb.setSmallIcon(c.getApplicationInfo().icon)
                    .setContentTitle(title)
                    .setContentText(text)
                    .setStyle(new Notification.BigTextStyle().bigText(text))
                    .setContentIntent(pi)
                    .setAutoCancel(true);
            if (Build.VERSION.SDK_INT < 26) nb.setPriority(Notification.PRIORITY_HIGH);
            NotificationManager nm = (NotificationManager) c.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm != null) nm.notify(id, nb.build());
        } catch (Exception ignored) {}
    }

    // ---------------- network ----------------
    private static String get(String url, String token, int[] codeOut) {
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) new URL(url).openConnection();
            con.setConnectTimeout(15000);
            con.setReadTimeout(20000);
            con.setRequestProperty("Authorization", "Bearer " + token);
            int code = con.getResponseCode();
            codeOut[0] = code;
            if (code != 200) return null;
            BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(), "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String ln;
            while ((ln = br.readLine()) != null) sb.append(ln);
            br.close();
            return sb.toString();
        } catch (Exception e) {
            codeOut[0] = -1;
            return null;
        } finally {
            if (con != null) con.disconnect();
        }
    }

    // POST عمومی — برای ورود مجدد با رمز عبور حساب (بازیابی پین اپ)، بدون نیاز به توکن قبلی
    public static String post(String url, String jsonBody, int[] codeOut) {
        HttpURLConnection con = null;
        try {
            con = (HttpURLConnection) new URL(url).openConnection();
            con.setConnectTimeout(15000);
            con.setReadTimeout(20000);
            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            byte[] out = jsonBody.getBytes("UTF-8");
            con.getOutputStream().write(out);
            int code = con.getResponseCode();
            codeOut[0] = code;
            java.io.InputStream is = (code >= 200 && code < 300) ? con.getInputStream() : con.getErrorStream();
            if (is == null) return null;
            BufferedReader br = new BufferedReader(new InputStreamReader(is, "UTF-8"));
            StringBuilder sb = new StringBuilder();
            String ln;
            while ((ln = br.readLine()) != null) sb.append(ln);
            br.close();
            return sb.toString();
        } catch (Exception e) {
            codeOut[0] = -1;
            return null;
        } finally {
            if (con != null) con.disconnect();
        }
    }

    // ---------------- helpers ----------------
    private static class Item {
        String key, channel, title, text, target;
        long sortTime;
    }

    private static String fmt(double n) {
        NumberFormat nf = NumberFormat.getInstance(new Locale("fa"));
        nf.setMaximumFractionDigits(2);
        return nf.format(n);
    }

    private static String sym(String cur) {
        if ("AFN".equals(cur)) return "؋";
        if ("IRT".equals(cur)) return "تومان";
        return cur == null ? "" : cur;
    }

    private static long parseIso(String s) {
        try {
            if (s == null) return 0;
            String t = s.replace("Z", "").replaceAll("\\.\\d+$", "").replace("T", " ");
            java.text.SimpleDateFormat f = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
            f.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
            return f.parse(t).getTime();
        } catch (Exception e) {
            return 0;
        }
    }

    // ---------------- main check (روی ترد پس‌زمینه صدا بزن) ----------------
    // خروجی: تعداد اعلان جدید (یا -1 اگه توکن منقضی بود)
    public static int checkNow(Context c) {
        synchronized (LOCK) {
            SharedPreferences p = sp(c);
            String token = p.getString("token", null);
            if (token == null) return 0;
            if (!flag(c, "all")) return 0;

            boolean firstRun = !p.getBoolean("init", false);
            LinkedHashSet<String> seen = new LinkedHashSet<String>();
            try {
                JSONArray sa = new JSONArray(p.getString("seen", "[]"));
                for (int i = 0; i < sa.length(); i++) seen.add(sa.getString(i));
            } catch (Exception ignored) {}

            List<Item> fresh = new ArrayList<Item>();
            boolean anyOk = false;
            int[] code = new int[1];

            // ===== ۱) بدهی و واریزی در «فروشگاه مشتری» (لینک‌های تاییدشده) =====
            String linksBody = get(DATA + "/links", token, code);
            if (code[0] == 401) { clearSession(c); return -1; }
            if (linksBody != null) {
                anyOk = true;
                try {
                    JSONArray links = new JSONObject(linksBody).getJSONArray("links");
                    for (int i = 0; i < links.length(); i++) {
                        JSONObject l = links.getJSONObject(i);
                        String store = l.getJSONObject("store").optString("name", "فروشگاه");
                        JSONArray txs = l.getJSONObject("customer").getJSONArray("transactions");
                        double balAfn = 0, balIrt = 0;
                        for (int j = 0; j < txs.length(); j++) {
                            JSONObject t = txs.getJSONObject(j);
                            double a = t.optDouble("amount", 0);
                            double d = "debt".equals(t.optString("type")) ? a : -a;
                            if ("IRT".equals(t.optString("currency"))) balIrt += d; else balAfn += d;
                        }
                        for (int j = 0; j < txs.length(); j++) {
                            JSONObject t = txs.getJSONObject(j);
                            String key = "tx:" + t.optString("id");
                            if (seen.contains(key)) continue;
                            Item it = new Item();
                            it.key = key;
                            it.channel = CH_TX;
                            it.target = "customerstore";
                            it.sortTime = parseIso(t.optString("date"));
                            boolean debt = "debt".equals(t.optString("type"));
                            String cur = t.optString("currency");
                            double bal = "IRT".equals(cur) ? balIrt : balAfn;
                            it.title = (debt ? "🔴 بدهی جدید" : "🟢 واریزی جدید") + " — " + store;
                            StringBuilder sb = new StringBuilder(fmt(t.optDouble("amount", 0)) + " " + sym(cur));
                            String note = t.optString("note", "");
                            if (note.length() > 0 && !"null".equals(note)) sb.append(" — ").append(note);
                            sb.append("\nمانده‌ی حساب شما: ").append(fmt(Math.abs(bal))).append(" ").append(sym(cur));
                            sb.append(bal > 0 ? " (بدهکار)" : bal < 0 ? " (بستانکار)" : " (تسویه)");
                            it.text = sb.toString();
                            fresh.add(it);
                        }
                    }
                } catch (Exception ignored) {}
            }

            // ===== ۲) وضعیت درخواست‌های عضویت من =====
            String jrBody = get(DATA + "/join-requests", token, code);
            if (jrBody != null) {
                anyOk = true;
                try {
                    JSONArray rq = new JSONObject(jrBody).getJSONArray("requests");
                    for (int i = 0; i < rq.length(); i++) {
                        JSONObject r = rq.getJSONObject(i);
                        String st = r.optString("status");
                        if ("pending".equals(st)) continue;
                        String rid = r.optString("id", r.optString("storeName") + r.optString("createdAt"));
                        String key = "jr:" + rid + ":" + st;
                        if (seen.contains(key)) continue;
                        Item it = new Item();
                        it.key = key; it.channel = CH_REQ; it.target = "notifications";
                        it.sortTime = parseIso(r.optString("createdAt"));
                        boolean ok = "approved".equals(st);
                        it.title = ok ? "✅ درخواست عضویت تایید شد" : "❌ درخواست عضویت رد شد";
                        it.text = "فروشگاه «" + r.optString("storeName") + "»"
                                + (!ok && r.optString("reason", "").length() > 0 ? "\nدلیل: " + r.optString("reason") : "");
                        fresh.add(it);
                    }
                } catch (Exception ignored) {}
            }

            // ===== ۳) پیام‌های مدیریت سیستم =====
            String bcBody = get(AUTH + "/me/broadcasts", token, code);
            if (bcBody != null) {
                anyOk = true;
                try {
                    JSONArray bc = new JSONObject(bcBody).getJSONArray("broadcasts");
                    for (int i = 0; i < bc.length(); i++) {
                        JSONObject b = bc.getJSONObject(i);
                        String msg = b.optString("message");
                        String key = "bc:" + b.optString("id", b.optString("date") + ":" + msg.hashCode());
                        if (seen.contains(key)) continue;
                        Item it = new Item();
                        it.key = key; it.channel = CH_SYS; it.target = "notifications";
                        it.sortTime = parseIso(b.optString("date"));
                        it.title = "📢 پیام مدیریت دفتر";
                        it.text = msg;
                        fresh.add(it);
                    }
                } catch (Exception ignored) {}
            }

            // ===== ۴) اشتراک: ۳ روز مانده / تمام‌شده =====
            String meBody = get(AUTH + "/me", token, code);
            if (meBody != null) {
                anyOk = true;
                try {
                    JSONObject sub = new JSONObject(meBody).getJSONObject("user").getJSONObject("subscription");
                    if (sub.optBoolean("active", false) && !sub.isNull("daysRemaining")) {
                        int left = sub.optInt("daysRemaining", 99);
                        if (left <= 3) {
                            String key = "sub:" + sub.optString("expiresAt") + ":" + left;
                            if (!seen.contains(key)) {
                                Item it = new Item();
                                it.key = key; it.channel = CH_SYS; it.target = "profile";
                                it.sortTime = System.currentTimeMillis();
                                it.title = "⏳ اشتراک شما رو به پایان است";
                                it.text = fmt(left) + " روز تا پایان اشتراک باقی مانده — برای تمدید اقدام کنید";
                                fresh.add(it);
                            }
                        }
                    }
                } catch (Exception ignored) {}
            }

            if (!anyOk) return 0; // آفلاین بود؛ دفعه‌ی بعد

            // اولین اجرا: فقط ثبت می‌کنیم، اعلان نمی‌ریزیم (تا تاریخچه‌ی قدیمی سیل نشه)
            boolean toShow = !firstRun;
            List<Item> out = new ArrayList<Item>();
            for (Item it : fresh) {
                if (toShow) {
                    boolean on = CH_TX.equals(it.channel) ? flag(c, "tx") : CH_REQ.equals(it.channel) ? flag(c, "req") : flag(c, "sys");
                    if (on) out.add(it);
                }
            }

            // اگه اجازه‌ی اعلان نیست، «دیده‌شده» ثبت نکن تا بعد از دادن اجازه بیاد
            if (toShow && !out.isEmpty() && !canNotify(c)) return 0;

            for (Item it : fresh) seen.add(it.key);
            // سقف حافظه
            if (seen.size() > SEEN_MAX) {
                int drop = seen.size() - SEEN_MAX;
                java.util.Iterator<String> iter = seen.iterator();
                while (drop-- > 0 && iter.hasNext()) { iter.next(); iter.remove(); }
            }
            p.edit().putString("seen", new JSONArray(seen).toString()).putBoolean("init", true).apply();

            if (out.isEmpty()) return 0;
            java.util.Collections.sort(out, new java.util.Comparator<Item>() {
                public int compare(Item a, Item b) { return Long.compare(a.sortTime, b.sortTime); }
            });
            if (out.size() > 5) {
                Item last = out.get(out.size() - 1);
                show(c, 9001, CH_TX, "🔔 " + fmt(out.size()) + " اعلان جدید در دفتر", "برای دیدن جزئیات، اپ را باز کنید", last.target);
            } else {
                for (Item it : out) show(c, Math.abs(it.key.hashCode()), it.channel, it.title, it.text, it.target);
            }
            return out.size();
        }
    }
}
