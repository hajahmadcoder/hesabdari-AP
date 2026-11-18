// ============================================================
// دفتر — کد اصلی MainActivity  (نسخه‌ی جدید)
// قفل امنیتی اپ + پل وب↔اپ (DaftarApp) + اعلان‌های اندروید
// این کد رو داخل بلوک "Add Source Directly" توی onCreate بذار
// (جایگزین کد قبلیِ daftar-app-lock.java)
// نیاز دارد: DaftarNotifier.java و DaftarNotifyJob.java (کنار همین فایل)
// ============================================================

final android.widget.FrameLayout rootLayout = (android.widget.FrameLayout) findViewById(android.R.id.content);
final android.webkit.WebView webview1 = (android.webkit.WebView) findViewById(R.id.webview1);
final android.content.Context appCtx = getApplicationContext();
final android.content.SharedPreferences lp = getSharedPreferences("daftar_lock", android.content.Context.MODE_PRIVATE);
final float dp = getResources().getDisplayMetrics().density;

// ---------------- ابزار قفل (پین با نمک + محدودیت تلاش) ----------------
class LockHelper {
    String toAscii(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch >= '\u06F0' && ch <= '\u06F9') sb.append((char) ('0' + (ch - '\u06F0')));
            else if (ch >= '\u0660' && ch <= '\u0669') sb.append((char) ('0' + (ch - '\u0660')));
            else sb.append(ch);
        }
        return sb.toString().trim();
    }
    String toHex(byte[] d) {
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b));
        return sb.toString();
    }
    String legacyHash(String pin) {
        try { return toHex(java.security.MessageDigest.getInstance("SHA-256").digest(pin.getBytes("UTF-8"))); }
        catch (Exception e) { return ""; }
    }
    String hashPin(String pin, String salt) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] d = (salt + ":" + pin).getBytes("UTF-8");
            for (int i = 0; i < 20000; i++) d = md.digest(d);
            return toHex(d);
        } catch (Exception e) { return ""; }
    }
    void storePin(String pin) {
        byte[] r = new byte[16];
        new java.security.SecureRandom().nextBytes(r);
        String salt = toHex(r);
        lp.edit().putString("pin_salt", salt).putString("pin_hash", hashPin(pin, salt)).putInt("pin_len", pin.length()).apply();
    }
    boolean validFormat(String pin) { return pin != null && pin.matches("[0-9]{4,6}"); }
    boolean hasPin() { return lp.contains("pin_hash"); }
    boolean bioAvail() {
        if (android.os.Build.VERSION.SDK_INT < 28) return false;
        try {
            android.hardware.fingerprint.FingerprintManager fm =
                (android.hardware.fingerprint.FingerprintManager) getSystemService(android.content.Context.FINGERPRINT_SERVICE);
            return fm != null && fm.isHardwareDetected() && fm.hasEnrolledFingerprints();
        } catch (Exception e) { return false; }
    }
    boolean bioOn() { return lp.getBoolean("bio_on", true) && bioAvail(); }
    boolean active() { return hasPin() || bioOn(); }
    boolean snoozed() { return lp.getLong("lock_snooze_until", 0) > System.currentTimeMillis(); }
    long lockAfterMs() { return lp.getLong("lock_after_ms", 30000L); }
    long lockedFor() {
        long left = lp.getLong("lock_until", 0) - System.currentTimeMillis();
        return left > 0 ? (left + 999) / 1000 : 0;
    }
    // خروجی: "ok" | "wrong" | "locked:<ثانیه>"
    String verify(String pin) {
        long left = lockedFor();
        if (left > 0) return "locked:" + left;
        String saved = lp.getString("pin_hash", "");
        String salt = lp.getString("pin_salt", "");
        boolean ok = salt.isEmpty() ? saved.equals(legacyHash(pin)) : saved.equals(hashPin(pin, salt));
        if (ok) {
            if (salt.isEmpty()) storePin(pin); // ارتقای پین قدیمی به نسخه‌ی نمک‌دار
            lp.edit().putInt("fails", 0).putLong("lock_until", 0).apply();
            return "ok";
        }
        int f = lp.getInt("fails", 0) + 1;
        long until = 0;
        if (f >= 5) {
            long secs = Math.min(300L, 30L << Math.min(4, f - 5));
            until = System.currentTimeMillis() + secs * 1000;
        }
        lp.edit().putInt("fails", f).putLong("lock_until", until).apply();
        return until > 0 ? "locked:" + lockedFor() : "wrong";
    }
    android.widget.TextView tv(String t, int sz, String color, boolean bold, int bottomDp) {
        android.widget.TextView v = new android.widget.TextView(MainActivity.this);
        v.setText(t);
        v.setTextSize(sz);
        v.setTextColor(android.graphics.Color.parseColor(color));
        if (bold) v.setTypeface(null, android.graphics.Typeface.BOLD);
        v.setGravity(android.view.Gravity.CENTER);
        android.widget.LinearLayout.LayoutParams p = new android.widget.LinearLayout.LayoutParams(
            android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT);
        p.bottomMargin = (int) (bottomDp * dp);
        v.setLayoutParams(p);
        return v;
    }
    android.widget.Button btn(String t, String bg, String fg) {
        android.widget.Button b = new android.widget.Button(MainActivity.this);
        b.setText(t);
        b.setTextColor(android.graphics.Color.parseColor(fg));
        b.setTextSize(15);
        b.setTypeface(null, android.graphics.Typeface.BOLD);
        b.setAllCaps(false);
        android.widget.LinearLayout.LayoutParams p = new android.widget.LinearLayout.LayoutParams(
            (int) (getResources().getDisplayMetrics().widthPixels * 0.75), (int) (50 * dp));
        p.bottomMargin = (int) (12 * dp);
        b.setLayoutParams(p);
        android.graphics.drawable.GradientDrawable g = new android.graphics.drawable.GradientDrawable();
        g.setColor(android.graphics.Color.parseColor(bg));
        g.setCornerRadius(30 * dp);
        g.setStroke((int) (1.5f * dp), android.graphics.Color.parseColor("#0D5C4C"));
        b.setBackground(g);
        return b;
    }
    // آیکون واقعی (نه ایموجی) — روی یک Bitmap کشیده می‌شود
    android.graphics.drawable.Drawable icon(String type, String colorHex, int sizeDp) {
        int size = (int) (sizeDp * dp);
        if (size < 1) size = 1;
        android.graphics.Bitmap bmp = android.graphics.Bitmap.createBitmap(size, size, android.graphics.Bitmap.Config.ARGB_8888);
        android.graphics.Canvas cv = new android.graphics.Canvas(bmp);
        android.graphics.Paint p = new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);
        p.setColor(android.graphics.Color.parseColor(colorHex));
        if ("lock".equals(type)) {
            p.setStyle(android.graphics.Paint.Style.STROKE);
            p.setStrokeWidth(size * 0.10f);
            p.setStrokeCap(android.graphics.Paint.Cap.ROUND);
            android.graphics.RectF shackle = new android.graphics.RectF(size * 0.28f, size * 0.10f, size * 0.72f, size * 0.56f);
            cv.drawArc(shackle, 180, 180, false, p);
            p.setStyle(android.graphics.Paint.Style.FILL);
            android.graphics.RectF body = new android.graphics.RectF(size * 0.18f, size * 0.44f, size * 0.82f, size * 0.88f);
            cv.drawRoundRect(body, size * 0.10f, size * 0.10f, p);
            android.graphics.Paint hole = new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);
            hole.setColor(android.graphics.Color.parseColor("#0D5C4C"));
            cv.drawCircle(size * 0.5f, size * 0.62f, size * 0.07f, hole);
            cv.drawRect(size * 0.46f, size * 0.62f, size * 0.54f, size * 0.78f, hole);
        } else {
            p.setStyle(android.graphics.Paint.Style.STROKE);
            p.setStrokeWidth(size * 0.075f);
            p.setStrokeCap(android.graphics.Paint.Cap.ROUND);
            float cx = size * 0.5f, cy = size * 0.58f;
            for (int i = 0; i < 4; i++) {
                float rx = size * (0.14f + i * 0.11f);
                float ry = rx * 1.15f;
                android.graphics.RectF rf = new android.graphics.RectF(cx - rx, cy - ry, cx + rx, cy + ry * 0.85f);
                cv.drawArc(rf, 150, 240, false, p);
            }
            cv.drawLine(cx, cy - size * 0.05f, cx, cy + size * 0.30f, p);
        }
        return new android.graphics.drawable.BitmapDrawable(getResources(), bmp);
    }
}
final LockHelper lh = new LockHelper();

final android.view.View[] lockView = new android.view.View[1];
final boolean[] fg = {true};
final long[] bgAt = {0};
final Runnable[] showLock = new Runnable[1];

final Runnable unlock = new Runnable() {
    public void run() {
        if (lockView[0] != null) { rootLayout.removeView(lockView[0]); lockView[0] = null; }
        webview1.setVisibility(android.view.View.VISIBLE);
    }
};

// ---------------- بازیابی با رمز عبور حساب (فراموشی پین اپ یا خرابی اثر انگشت) ----------------
final Runnable[] showRecovery = new Runnable[1];
showRecovery[0] = new Runnable() {
    public void run() {
        final android.widget.EditText userIn = new android.widget.EditText(MainActivity.this);
        userIn.setHint("نام کاربری حساب");
        userIn.setText(lp.getString("acct_user", ""));
        final android.widget.EditText passIn = new android.widget.EditText(MainActivity.this);
        passIn.setHint("رمز عبور حساب");
        passIn.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        final android.widget.TextView err = lh.tv("", 12, "#C0392B", false, 0);
        int pad = (int) (20 * dp);
        android.widget.LinearLayout box = new android.widget.LinearLayout(MainActivity.this);
        box.setOrientation(android.widget.LinearLayout.VERTICAL);
        box.setPadding(pad, pad, pad, 0);
        box.addView(userIn);
        box.addView(passIn);
        box.addView(err);
        final android.app.AlertDialog dlg = new android.app.AlertDialog.Builder(MainActivity.this)
            .setTitle("بازیابی با رمز عبور حساب")
            .setMessage("پین فعلی اپ حذف می‌شود و بعد از ورود باید یک پین جدید بگذارید")
            .setView(box)
            .setPositiveButton("بازیابی", null)
            .setNegativeButton("انصراف", null)
            .create();
        dlg.setOnShowListener(new android.content.DialogInterface.OnShowListener() {
            public void onShow(android.content.DialogInterface d) {
                dlg.getButton(android.app.AlertDialog.BUTTON_POSITIVE).setOnClickListener(new android.view.View.OnClickListener() {
                    public void onClick(android.view.View v) {
                        final String u = userIn.getText().toString().trim();
                        final String pw = passIn.getText().toString();
                        if (u.length() == 0 || pw.length() == 0) { err.setText("نام کاربری و رمز عبور را وارد کنید"); return; }
                        err.setText("در حال بررسی...");
                        new Thread(new Runnable() {
                            public void run() {
                                int[] code = new int[1];
                                String body = null;
                                try {
                                    org.json.JSONObject req = new org.json.JSONObject();
                                    req.put("username", u);
                                    req.put("password", pw);
                                    body = DaftarNotifier.post(DaftarNotifier.AUTH + "/auth/login", req.toString(), code);
                                } catch (Exception e) {}
                                String t = null;
                                if (code[0] == 200 && body != null) {
                                    try { t = new org.json.JSONObject(body).optString("token", null); } catch (Exception e) {}
                                }
                                final String token = t;
                                final String errMsg = (token != null) ? null : (code[0] == -1 ? "اتصال اینترنت برقرار نیست" : "نام کاربری یا رمز عبور اشتباه است");
                                runOnUiThread(new Runnable() {
                                    public void run() {
                                        if (token == null) { err.setText(errMsg); return; }
                                        lp.edit().remove("pin_hash").remove("pin_salt").remove("pin_len").putString("acct_user", u).apply();
                                        DaftarNotifier.saveSession(appCtx, token);
                                        try { dlg.dismiss(); } catch (Exception e) {}
                                        unlock.run();
                                        android.widget.Toast.makeText(appCtx, "دسترسی بازیابی شد. از پروفایل ← امنیت حساب یک پین جدید تنظیم کنید", android.widget.Toast.LENGTH_LONG).show();
                                        final String tk = token.replace("\\", "\\\\").replace("'", "\\'");
                                        webview1.post(new Runnable() {
                                            public void run() {
                                                webview1.evaluateJavascript("try{localStorage.setItem('daftar-token','" + tk + "');}catch(e){}", null);
                                                webview1.reload();
                                            }
                                        });
                                    }
                                });
                            }
                        }).start();
                    }
                });
            }
        });
        dlg.show();
    }
};

// ---------------- صفحه‌ی قفل ----------------
showLock[0] = new Runnable() {
    public void run() {
        if (lockView[0] != null || !lh.active()) return;
        webview1.setVisibility(android.view.View.GONE);
        final boolean pinMode = lh.hasPin();
        final boolean bio = lh.bioOn();

        android.widget.LinearLayout root = new android.widget.LinearLayout(MainActivity.this);
        root.setOrientation(android.widget.LinearLayout.VERTICAL);
        root.setGravity(android.view.Gravity.CENTER);
        root.setBackgroundColor(android.graphics.Color.parseColor("#F2EDE2"));
        root.setLayoutParams(new android.widget.FrameLayout.LayoutParams(
            android.widget.FrameLayout.LayoutParams.MATCH_PARENT, android.widget.FrameLayout.LayoutParams.MATCH_PARENT));
        root.setClickable(true);

        android.widget.FrameLayout iconWrap = new android.widget.FrameLayout(MainActivity.this);
        int cs = (int) (100 * dp);
        android.widget.LinearLayout.LayoutParams ip = new android.widget.LinearLayout.LayoutParams(cs, cs);
        ip.bottomMargin = (int) (24 * dp);
        iconWrap.setLayoutParams(ip);
        android.graphics.drawable.GradientDrawable circle = new android.graphics.drawable.GradientDrawable();
        circle.setShape(android.graphics.drawable.GradientDrawable.OVAL);
        circle.setColor(android.graphics.Color.parseColor("#0D5C4C"));
        iconWrap.setBackground(circle);
        android.widget.ImageView lockGlyph = new android.widget.ImageView(MainActivity.this);
        lockGlyph.setImageDrawable(lh.icon("lock", "#FFFFFF", 44));
        android.widget.FrameLayout.LayoutParams gp = new android.widget.FrameLayout.LayoutParams((int) (44 * dp), (int) (44 * dp));
        gp.gravity = android.view.Gravity.CENTER;
        lockGlyph.setLayoutParams(gp);
        iconWrap.addView(lockGlyph);
        root.addView(iconWrap);
        root.addView(lh.tv("دفتر قفل است", 19, "#0D3D33", true, 8));
        root.addView(lh.tv(pinMode ? "پین را وارد کنید" + (bio ? " یا اثر انگشت بزنید" : "") : "برای ورود، اثر انگشت خود را لمس کنید", 14, "#5A6B66", false, 22));

        final android.widget.EditText pinInput = new android.widget.EditText(MainActivity.this);
        final android.widget.TextView errText = lh.tv("", 13, "#C0392B", false, 12);

        if (pinMode) {
            pinInput.setInputType(android.text.InputType.TYPE_CLASS_NUMBER | android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD);
            pinInput.setHint("پین");
            pinInput.setGravity(android.view.Gravity.CENTER);
            pinInput.setTextSize(22);
            pinInput.setBackgroundColor(android.graphics.Color.WHITE);
            android.widget.LinearLayout.LayoutParams pp = new android.widget.LinearLayout.LayoutParams(
                (int) (getResources().getDisplayMetrics().widthPixels * 0.75), (int) (56 * dp));
            pp.bottomMargin = (int) (10 * dp);
            pinInput.setLayoutParams(pp);
            root.addView(pinInput);
            root.addView(errText);

            final Runnable submit = new Runnable() {
                public void run() {
                    String r = lh.verify(lh.toAscii(pinInput.getText().toString()));
                    if ("ok".equals(r)) { unlock.run(); return; }
                    errText.setText(r.startsWith("locked:") ? "تلاش بیش از حد. " + r.substring(7) + " ثانیه صبر کنید" : "پین اشتباه است");
                    pinInput.setText("");
                }
            };
            pinInput.addTextChangedListener(new android.text.TextWatcher() {
                public void beforeTextChanged(CharSequence s, int a, int b, int c) {}
                public void onTextChanged(CharSequence s, int a, int b, int c) {}
                public void afterTextChanged(android.text.Editable e) {
                    int need = lp.getInt("pin_len", 0);
                    if (need > 0 && e.length() == need) submit.run();
                }
            });
            android.widget.Button enter = lh.btn("ورود", "#0D5C4C", "#FFFFFF");
            enter.setOnClickListener(new android.view.View.OnClickListener() {
                public void onClick(android.view.View v) { submit.run(); }
            });
            root.addView(enter);
        }

        final Runnable startFp = new Runnable() {
            public void run() {
                try {
                    if (androidx.core.app.ActivityCompat.checkSelfPermission(MainActivity.this, android.Manifest.permission.USE_FINGERPRINT)
                            != android.content.pm.PackageManager.PERMISSION_GRANTED) return;
                    android.hardware.fingerprint.FingerprintManager fm =
                        (android.hardware.fingerprint.FingerprintManager) getSystemService(android.content.Context.FINGERPRINT_SERVICE);
                    fm.authenticate(null, new android.os.CancellationSignal(), 0,
                        new android.hardware.fingerprint.FingerprintManager.AuthenticationCallback() {
                            @Override public void onAuthenticationSucceeded(android.hardware.fingerprint.FingerprintManager.AuthenticationResult result) { unlock.run(); }
                            @Override public void onAuthenticationFailed() {
                                android.widget.Toast.makeText(appCtx, "اثر انگشت شناسایی نشد، دوباره تلاش کنید", android.widget.Toast.LENGTH_SHORT).show();
                            }
                            @Override public void onAuthenticationError(int errorCode, CharSequence errString) {
                                if (errString != null) android.widget.Toast.makeText(appCtx, errString.toString(), android.widget.Toast.LENGTH_SHORT).show();
                            }
                        }, null);
                } catch (Exception e) {}
            }
        };
        if (bio) {
            String fpFg = pinMode ? "#0D5C4C" : "#FFFFFF";
            android.widget.Button fpBtn = lh.btn("باز کردن با اثر انگشت", pinMode ? "#FFFFFF" : "#0D5C4C", fpFg);
            fpBtn.setCompoundDrawablesWithIntrinsicBounds(lh.icon("fingerprint", fpFg, 20), null, null, null);
            fpBtn.setCompoundDrawablePadding((int) (8 * dp));
            fpBtn.setOnClickListener(new android.view.View.OnClickListener() {
                public void onClick(android.view.View v) { startFp.run(); }
            });
            root.addView(fpBtn);
        }

        android.widget.TextView recoveryLink = lh.tv("پین را فراموش کرده‌اید یا اثر انگشت کار نمی‌کند؟", 12, "#0D5C4C", false, 0);
        recoveryLink.setPaintFlags(recoveryLink.getPaintFlags() | android.graphics.Paint.UNDERLINE_TEXT_FLAG);
        android.widget.LinearLayout.LayoutParams rlp = new android.widget.LinearLayout.LayoutParams(
            android.widget.LinearLayout.LayoutParams.WRAP_CONTENT, android.widget.LinearLayout.LayoutParams.WRAP_CONTENT);
        rlp.topMargin = (int) (18 * dp);
        recoveryLink.setLayoutParams(rlp);
        recoveryLink.setOnClickListener(new android.view.View.OnClickListener() {
            public void onClick(android.view.View v) { showRecovery[0].run(); }
        });
        root.addView(recoveryLink);

        rootLayout.addView(root);
        lockView[0] = root;
        if (bio) startFp.run();
    }
};

// قفل هنگام باز شدن اپ
if (lh.active() && !lh.snoozed()) showLock[0].run();

// ---------------- بررسی دوره‌ای اعلان‌ها وقتی اپ باز است ----------------
final android.os.Handler mainH = new android.os.Handler(android.os.Looper.getMainLooper());
final Runnable poll = new Runnable() {
    public void run() {
        if (!fg[0]) return;
        new Thread(new Runnable() {
            public void run() { try { DaftarNotifier.checkNow(appCtx); } catch (Exception e) {} }
        }).start();
        mainH.postDelayed(this, 60000);
    }
};

// قفل مجدد بعد از ۳۰ ثانیه در پس‌زمینه بودن + شروع/توقف بررسی اعلان
getApplication().registerActivityLifecycleCallbacks(new android.app.Application.ActivityLifecycleCallbacks() {
    public void onActivityCreated(android.app.Activity a, android.os.Bundle b) {}
    public void onActivityStarted(android.app.Activity a) {
        if (a != MainActivity.this) return;
        fg[0] = true;
        if (bgAt[0] > 0 && System.currentTimeMillis() - bgAt[0] > lh.lockAfterMs() && lh.active() && !lh.snoozed()) showLock[0].run();
        bgAt[0] = 0;
        mainH.removeCallbacks(poll);
        mainH.post(poll);
        // تا وقتی اجازه‌ی اعلان داده نشده، هر بار که اپ باز می‌شود دوباره درخواست می‌شود
        if (android.os.Build.VERSION.SDK_INT >= 33 && !DaftarNotifier.canNotify(appCtx)) {
            try { requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 101); } catch (Exception e) {}
        }
    }
    public void onActivityResumed(android.app.Activity a) {}
    public void onActivityPaused(android.app.Activity a) {}
    public void onActivityStopped(android.app.Activity a) {
        if (a != MainActivity.this) return;
        fg[0] = false;
        bgAt[0] = System.currentTimeMillis();
    }
    public void onActivitySaveInstanceState(android.app.Activity a, android.os.Bundle b) {}
    public void onActivityDestroyed(android.app.Activity a) {
        if (a != MainActivity.this) return;
        mainH.removeCallbacks(poll);
        getApplication().unregisterActivityLifecycleCallbacks(this);
    }
});

// ---------------- پل وب ↔ اپ  (window.DaftarApp داخل سایت) ----------------
final Object bridge = new Object() {
    // ----- قفل -----
    @android.webkit.JavascriptInterface
    public String lockInfo() {
        return "{\"pin\":" + lh.hasPin() + ",\"bio\":" + lp.getBoolean("bio_on", true) + ",\"bioAvailable\":" + lh.bioAvail() + "}";
    }
    @android.webkit.JavascriptInterface
    public String setPin(String newPin, String oldPin) {
        String np = lh.toAscii(newPin);
        if (!lh.validFormat(np)) return "bad_format";
        if (lh.hasPin()) {
            String r = lh.verify(lh.toAscii(oldPin));
            if (!"ok".equals(r)) return r;
        }
        lh.storePin(np);
        return "ok";
    }
    @android.webkit.JavascriptInterface
    public String removePin(String pin) {
        if (!lh.hasPin()) return "ok";
        String r = lh.verify(lh.toAscii(pin));
        if ("ok".equals(r)) lp.edit().remove("pin_hash").remove("pin_salt").remove("pin_len").apply();
        return r;
    }
    @android.webkit.JavascriptInterface
    public String setBiometric(boolean on) {
        if (on && !lh.bioAvail()) return "unavailable";
        lp.edit().putBoolean("bio_on", on).apply();
        return "ok";
    }
    @android.webkit.JavascriptInterface
    public void lockNow() {
        runOnUiThread(new Runnable() { public void run() { showLock[0].run(); } });
    }
    @android.webkit.JavascriptInterface
    public void exitApp() {
        runOnUiThread(new Runnable() { public void run() { finish(); } });
    }
    @android.webkit.JavascriptInterface
    public String lockTimingInfo() {
        long after = lp.getLong("lock_after_ms", 30000L);
        long remain = Math.max(0, lp.getLong("lock_snooze_until", 0) - System.currentTimeMillis());
        return "{\"afterMs\":" + after + ",\"snoozeRemainMs\":" + remain + "}";
    }
    @android.webkit.JavascriptInterface
    public void setLockAfterMs(String ms) {
        try { lp.edit().putLong("lock_after_ms", Long.parseLong(ms)).apply(); } catch (Exception e) {}
    }
    @android.webkit.JavascriptInterface
    public void snoozeLock(String hours) {
        try {
            long h = Long.parseLong(hours);
            lp.edit().putLong("lock_snooze_until", System.currentTimeMillis() + h * 3600000L).apply();
        } catch (Exception e) {}
    }
    @android.webkit.JavascriptInterface
    public void cancelSnooze() {
        lp.edit().remove("lock_snooze_until").apply();
    }

    // ----- نشست و اعلان‌ها -----
    @android.webkit.JavascriptInterface
    public void saveSession(String token) {
        DaftarNotifier.saveSession(appCtx, token);
        DaftarNotifier.ensureChannels(appCtx);
        DaftarNotifier.schedule(appCtx);
    }
    @android.webkit.JavascriptInterface
    public void saveUsername(String username) {
        if (username != null && username.length() > 0) lp.edit().putString("acct_user", username).apply();
    }
    @android.webkit.JavascriptInterface
    public void setUser(String id) {
        DaftarNotifier.setUser(appCtx, id);
        new Thread(new Runnable() {
            public void run() { try { DaftarNotifier.checkNow(appCtx); } catch (Exception e) {} }
        }).start();
    }
    @android.webkit.JavascriptInterface
    public void clearSession() { DaftarNotifier.clearSession(appCtx); }
    @android.webkit.JavascriptInterface
    public String notifyInfo() {
        return "{\"allowed\":" + DaftarNotifier.canNotify(appCtx)
            + ",\"all\":" + DaftarNotifier.flag(appCtx, "all")
            + ",\"tx\":" + DaftarNotifier.flag(appCtx, "tx")
            + ",\"req\":" + DaftarNotifier.flag(appCtx, "req")
            + ",\"sys\":" + DaftarNotifier.flag(appCtx, "sys") + "}";
    }
    @android.webkit.JavascriptInterface
    public void setNotifyFlag(String key, boolean on) {
        if ("all".equals(key) || "tx".equals(key) || "req".equals(key) || "sys".equals(key)) DaftarNotifier.setFlag(appCtx, key, on);
    }
    @android.webkit.JavascriptInterface
    public void requestNotifyPermission() {
        runOnUiThread(new Runnable() {
            public void run() {
                if (android.os.Build.VERSION.SDK_INT >= 33) {
                    requestPermissions(new String[]{"android.permission.POST_NOTIFICATIONS"}, 101);
                } else {
                    openSystemNotifySettings();
                }
            }
        });
    }
    @android.webkit.JavascriptInterface
    public void openSystemNotifySettings() {
        try {
            android.content.Intent i;
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                i = new android.content.Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS);
                i.putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, getPackageName());
            } else {
                i = new android.content.Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                i.setData(android.net.Uri.parse("package:" + getPackageName()));
            }
            i.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
        } catch (Exception e) {}
    }
    @android.webkit.JavascriptInterface
    public void openBatterySettings() {
        try {
            android.content.Intent i = new android.content.Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS);
            i.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
        } catch (Exception e) {}
    }
    @android.webkit.JavascriptInterface
    public void testNotify() {
        DaftarNotifier.show(appCtx, 9002, DaftarNotifier.CH_SYS, "✅ اعلان‌های دفتر فعال است", "از این پس بدهی، واریزی و پیام‌های سیستم را همین‌جا می‌بینید", "notifications");
    }
};
webview1.addJavascriptInterface(bridge, "DaftarApp");

// اگه از قبل وارد حساب شده بود، کار پس‌زمینه‌ی اعلان رو (دوباره) برنامه‌ریزی کن
DaftarNotifier.schedule(appCtx);

// ============================================================
// از اینجا به بعد همون کد WebView اصلیه (تغییری نکرده جز آدرس و برندینگ)
// ============================================================

final android.webkit.ValueCallback[] mFilePathCallback = new android.webkit.ValueCallback[1];
final String mainUrl = "https://hesabdariap.pages.dev/";
final String mainOrigin = mainUrl.substring(0, mainUrl.indexOf('/', 8) + 1);

webview1.getSettings().setJavaScriptEnabled(true);
webview1.getSettings().setDomStorageEnabled(true);
webview1.getSettings().setDatabaseEnabled(true);
webview1.getSettings().setLoadWithOverviewMode(true);
webview1.getSettings().setUseWideViewPort(true);
webview1.getSettings().setAllowFileAccess(true);
webview1.getSettings().setAllowContentAccess(true);
webview1.getSettings().setMediaPlaybackRequiresUserGesture(false);
webview1.getSettings().setGeolocationEnabled(true);
webview1.getSettings().setCacheMode(android.webkit.WebSettings.LOAD_DEFAULT);
webview1.getSettings().setSupportZoom(true);
webview1.getSettings().setBuiltInZoomControls(false);
webview1.getSettings().setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
android.webkit.CookieManager.getInstance().setAcceptCookie(true);
android.webkit.CookieManager.getInstance().setAcceptThirdPartyCookies(webview1, true);

if (android.os.Build.VERSION.SDK_INT >= 23) {
    if (checkSelfPermission(android.Manifest.permission.ACCESS_FINE_LOCATION) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
        requestPermissions(new String[]{android.Manifest.permission.ACCESS_FINE_LOCATION, android.Manifest.permission.CAMERA, android.Manifest.permission.WRITE_EXTERNAL_STORAGE}, 100);
    }
}

String logoBase64 = "";
try {
    android.graphics.Bitmap logoBitmap = android.graphics.BitmapFactory.decodeResource(getResources(), R.drawable.app_logo);
    java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
    logoBitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, baos);
    logoBase64 = android.util.Base64.encodeToString(baos.toByteArray(), android.util.Base64.NO_WRAP);
} catch (Exception e) {
    logoBase64 = "";
}
final String logoImgTag = logoBase64.isEmpty() ? "" : "<img class='logo' src='data:image/png;base64," + logoBase64 + "'/>";

// ⚠️ این دوتا رو با آیدی/کانال تلگرام خودت پر کن
final String SUPPORT_TG_USERNAME = "YOUR_SUPPORT_USERNAME";
final String CHANNEL_TG_URL = "https://t.me/YOUR_CHANNEL";

final String errorPageHtml = "<!DOCTYPE html><html><head><meta charset='utf-8'>" +
    "<meta name='viewport' content='width=device-width, initial-scale=1.0'>" +
    "<style>" +
    "*{margin:0;padding:0;box-sizing:border-box;}" +
    "body{background:#f2ede2;font-family:sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;direction:rtl;}" +
    ".box{text-align:center;padding:30px;max-width:360px;width:100%;}" +
    ".logo{width:80px;height:80px;margin:0 auto 24px;display:block;border-radius:18px;}" +
    ".icon{width:70px;height:70px;margin:0 auto 18px;}" +
    "h2{color:#0d3d33;font-size:21px;margin-bottom:10px;font-weight:700;}" +
    "p{color:#5a6b66;font-size:14px;line-height:1.7;margin-bottom:26px;}" +
    "button{background:#0d5c4c;color:#fff;border:none;padding:14px 44px;border-radius:30px;font-size:16px;font-family:sans-serif;font-weight:600;width:100%;margin-bottom:14px;}" +
    "button:active{background:#0a4a3d;}" +
    ".divider{display:flex;align-items:center;color:#9aa8a4;font-size:12px;margin:22px 0;}" +
    ".divider::before,.divider::after{content:'';flex:1;height:1px;background:#dcd5c8;}" +
    ".divider span{padding:0 12px;}" +
    ".tg-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:#fff;color:#0d3d33;border:1.5px solid #d8e6e0;padding:13px 20px;border-radius:14px;font-size:14px;font-weight:600;margin-bottom:10px;text-decoration:none;}" +
    ".tg-btn svg{flex-shrink:0;}" +
    "</style></head><body>" +
    "<div class='box'>" +
    logoImgTag +
    "<svg class='icon' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'>" +
    "<path d='M1 9L3 11C7.97 6.03 16.03 6.03 21 11L23 9C16.93 2.93 7.08 2.93 1 9Z' fill='#0d5c4c'/>" +
    "<path d='M5 13L7 15C9.76 12.24 14.24 12.24 17 15L19 13C15.14 9.14 8.87 9.14 5 13Z' fill='#0d5c4c'/>" +
    "<path d='M9 17L12 20L15 17C13.35 15.34 10.66 15.34 9 17Z' fill='#0d5c4c'/>" +
    "<line x1='2' y1='2' x2='22' y2='22' stroke='#d9534f' stroke-width='2.5'/>" +
    "</svg>" +
    "<h2>اتصال به اینترنت برقرار نیست</h2>" +
    "<p>لطفاً اتصال اینترنت خود را بررسی کرده و دوباره تلاش کنید</p>" +
    "<button onclick=\"window.location.href='retry:reload'\">تلاش مجدد</button>" +
    "<div class='divider'><span>یا از طریق تلگرام در ارتباط باشید</span></div>" +
    "<a class='tg-btn' href='tg-support:open'>پشتیبانی</a>" +
    "<a class='tg-btn' href='tg-channel:open'>کانال رسمی دفتر</a>" +
    "</div></body></html>";

webview1.setWebViewClient(new android.webkit.WebViewClient() {
    boolean errorShown = false;

    @Override
    public boolean shouldOverrideUrlLoading(android.webkit.WebView view, String url) {
        if (url.equals("retry:reload")) {
            errorShown = false;
            view.loadUrl(mainUrl);
            return true;
        } else if (url.equals("tg-support:open")) {
            try {
                startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("tg://resolve?domain=" + SUPPORT_TG_USERNAME)));
            } catch (Exception e) {
                startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse("https://t.me/" + SUPPORT_TG_USERNAME)));
            }
            return true;
        } else if (url.equals("tg-channel:open")) {
            try {
                startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(CHANNEL_TG_URL)));
            } catch (Exception e) {}
            return true;
        } else if (url.startsWith("tel:")) {
            startActivity(new android.content.Intent(android.content.Intent.ACTION_DIAL, android.net.Uri.parse(url)));
            return true;
        } else if (url.startsWith("mailto:")) {
            startActivity(new android.content.Intent(android.content.Intent.ACTION_SENDTO, android.net.Uri.parse(url)));
            return true;
        } else if (url.startsWith("whatsapp:") || url.startsWith("intent:")) {
            try {
                startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url)));
            } catch (Exception e) {}
            return true;
        }
        // لینک‌های بیرونی (غیر از خود دفتر) توی مرورگر باز می‌شن؛ پل DaftarApp فقط برای خود سایت دفتر فعاله
        if (url.startsWith("http") && !url.startsWith(mainOrigin)) {
            try { startActivity(new android.content.Intent(android.content.Intent.ACTION_VIEW, android.net.Uri.parse(url))); } catch (Exception e) {}
            return true;
        }
        view.loadUrl(url);
        return true;
    }

    @Override
    public void onReceivedError(android.webkit.WebView view, int errorCode, String description, String failingUrl) {
        if (!errorShown && failingUrl != null && failingUrl.startsWith(mainUrl.substring(0, mainUrl.indexOf('/', 8)))) {
            errorShown = true;
            view.loadDataWithBaseURL(null, errorPageHtml, "text/html", "UTF-8", null);
        }
    }

    @Override
    public void onPageFinished(android.webkit.WebView view, String url) {
        if (url != null && url.equals(mainUrl)) {
            errorShown = false;
        }
    }
});

webview1.setWebChromeClient(new android.webkit.WebChromeClient() {
    @Override
    public void onGeolocationPermissionsShowPrompt(String origin, android.webkit.GeolocationPermissions.Callback callback) {
        callback.invoke(origin, true, false);
    }

    @Override
    public boolean onShowFileChooser(android.webkit.WebView webView, android.webkit.ValueCallback<android.net.Uri[]> filePathCallback, android.webkit.WebChromeClient.FileChooserParams fileChooserParams) {
        if (mFilePathCallback[0] != null) {
            mFilePathCallback[0].onReceiveValue(null);
        }
        mFilePathCallback[0] = filePathCallback;
        android.content.Intent intent = fileChooserParams.createIntent();
        try {
            startActivityForResult(intent, 200);
        } catch (Exception e) {
            mFilePathCallback[0] = null;
            return false;
        }
        return true;
    }
});

webview1.setDownloadListener(new android.webkit.DownloadListener() {
    @Override
    public void onDownloadStart(String url, String userAgent, String contentDisposition, String mimeType, long contentLength) {
        android.app.DownloadManager.Request request = new android.app.DownloadManager.Request(android.net.Uri.parse(url));
        request.setMimeType(mimeType);
        request.addRequestHeader("User-Agent", userAgent);
        request.setDescription("در حال دانلود فایل...");
        request.setTitle(android.webkit.URLUtil.guessFileName(url, contentDisposition, mimeType));
        request.allowScanningByMediaScanner();
        request.setNotificationVisibility(android.app.DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
        request.setDestinationInExternalPublicDir(android.os.Environment.DIRECTORY_DOWNLOADS, android.webkit.URLUtil.guessFileName(url, contentDisposition, mimeType));
        android.app.DownloadManager dm = (android.app.DownloadManager) getSystemService(android.content.Context.DOWNLOAD_SERVICE);
        dm.enqueue(request);
        android.widget.Toast.makeText(getApplicationContext(), "دانلود شروع شد", android.widget.Toast.LENGTH_SHORT).show();
    }
});

// اگه کاربر از روی یک اعلان اومده، مستقیم بره همون بخش (?open=customerstore | notifications | profile)
String openTarget = null;
try { openTarget = getIntent() != null ? getIntent().getStringExtra("daftar_open") : null; } catch (Exception e) {}
if (openTarget != null && !openTarget.matches("[a-z\\-]{3,20}")) openTarget = null;
webview1.loadUrl(openTarget != null ? mainUrl + "?open=" + openTarget : mainUrl);
