// ============================================================
// دفتر — کار پس‌زمینه‌ی اعلان‌ها (هر ~۱۵ دقیقه، حتی وقتی اپ بسته است)
// Sketchware Pro: Java/Kotlin Manager → Add class → اسمش: DaftarNotifyJob
// ⚠️ خط package باید دقیقاً با package اپ تو یکی باشه
// ============================================================
package hesabdari.AP.com;

import android.app.job.JobParameters;
import android.app.job.JobService;

public class DaftarNotifyJob extends JobService {
    @Override
    public boolean onStartJob(final JobParameters params) {
        new Thread(new Runnable() {
            public void run() {
                try { DaftarNotifier.checkNow(getApplicationContext()); } catch (Exception ignored) {}
                jobFinished(params, false);
            }
        }).start();
        return true;
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return true;
    }
}
