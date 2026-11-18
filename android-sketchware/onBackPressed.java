// ============================================================
// دفتر — کد دکمه‌ی برگشت گوشی
// در Sketchware Pro: برو به تب Event → روی «onBackPressed» بزن
// → «Add Source Directly» → این کد را بگذار
// (این باید جایگزین هر کد قبلی در همین بلوک شود، نه اضافه به آن)
// ============================================================

if (webview1.canGoBack()) {
    webview1.goBack();
} else {
    // به‌جای دیالوگ پیش‌فرض گوشی، همان پنجره‌ی طراحی‌شده‌ی خودِ اپ را نشان می‌دهد
    webview1.evaluateJavascript(
        "if (typeof confirmExitApp === 'function') { confirmExitApp(); }",
        null
    );
}
