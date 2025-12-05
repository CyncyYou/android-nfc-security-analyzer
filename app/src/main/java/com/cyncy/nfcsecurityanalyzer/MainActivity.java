//package com.cyncy.nfcsecurityanalyzer;
//
//import androidx.appcompat.app.AppCompatActivity;
//
//import android.app.PendingIntent;
//import android.content.Intent;
//import android.nfc.NfcAdapter;
//import android.nfc.Tag;
//import android.os.Bundle;
//import android.widget.TextView;
//
//import java.util.Arrays;

package com.cyncy.nfcsecurityanalyzer;

import androidx.appcompat.app.AppCompatActivity;

import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.tech.Ndef;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Bundle;
import android.widget.TextView;

import java.util.Arrays;

public class MainActivity extends AppCompatActivity {

    private NfcAdapter nfcAdapter;
    private PendingIntent pendingIntent;
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textView = findViewById(R.id.textView);

        // get NFC adaptor
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        // set foreground PendingIntent
        pendingIntent = PendingIntent.getActivity(
                this,
                0,
                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE
        );

        textView.setText("\n\nPlease scan a NFC card");
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (nfcAdapter != null)
            nfcAdapter.enableForegroundDispatch(this, pendingIntent, null, null);
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (nfcAdapter != null)
            nfcAdapter.disableForegroundDispatch(this);
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        analyzeTag(intent);
    }


    // ------------------------------
    //   NFC tag analysis main access
    // ------------------------------
    private void analyzeTag(Intent intent) {

        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
        if (tag == null) {
            textView.setText("can't detect NFC");
            return;
        }

        StringBuilder report = new StringBuilder();
        report.append("\n\n=== NFC security analysis report ===\n\n");

        report.append(getTagId(tag));
        report.append(getTechList(tag));
        report.append(checkCloneRisk(tag));
        report.append(readNdefContent(tag));

        textView.setText(report.toString());
    }


    // ------------------------------
    //   function code
    // ------------------------------

    private String getTagId(Tag tag) {
        byte[] id = tag.getId();
        return "📌 ID (UID): " + bytesToHex(id) + "\n\n";
    }

    private String getTechList(Tag tag) {
        StringBuilder sb = new StringBuilder("📌 Tech List:\n");
        for (String tech : tag.getTechList()) {
            sb.append(" - ").append(tech).append("\n");
        }
        sb.append("\n");
        return sb.toString();
    }

    private String checkCloneRisk(Tag tag) {
        byte[] id = tag.getId();
        String note;

        if (id.length == 4) {
            note = "⚠ warning：UID is 4 byte，Might be clone byte.\n\n";
        } else {
            note = "✔ UID not common clone card format\n\n";
        }

        return note;
    }

    private String readNdefContent(Tag tag) {
        StringBuilder sb = new StringBuilder("📌 NDEF data:\n");

        try {
            Ndef ndef = Ndef.get(tag);
            if (ndef == null) {
                sb.append("No NDEF data\n");
                return sb.toString();
            }

            ndef.connect();
            NdefMessage msg = ndef.getNdefMessage();

            if (msg == null) {
                sb.append("tag is empty\n");
                return sb.toString();
            }

            for (NdefRecord record : msg.getRecords()) {
                sb.append(" - ");
                sb.append(new String(record.getPayload()));
                sb.append("\n");
            }

            ndef.close();

        } catch (Exception e) {
            sb.append("Error reading NDEF\n");
        }

        sb.append("\n");
        return sb.toString();
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}


//public class MainActivity extends AppCompatActivity {
//
//    private NfcAdapter nfcAdapter;
//    private PendingIntent pendingIntent;
//    private TextView textView;
//
//    @Override
//    protected void onCreate(Bundle savedInstanceState) {
//        super.onCreate(savedInstanceState);
//        setContentView(R.layout.activity_main);
//
//        textView = findViewById(R.id.textView);
//
//        nfcAdapter = NfcAdapter.getDefaultAdapter(this);
//
//        pendingIntent = PendingIntent.getActivity(
//                this, 0,
//                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
//                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_MUTABLE
//        );
//    }
//
//    @Override
//    protected void onResume() {
//        super.onResume();
//        if (nfcAdapter != null)
//            nfcAdapter.enableForegroundDispatch(this, pendingIntent, null, null);
//    }
//
//    @Override
//    protected void onPause() {
//        super.onPause();
//        if (nfcAdapter != null)
//            nfcAdapter.disableForegroundDispatch(this);
//    }
//
//    @Override
//    protected void onNewIntent(Intent intent) {
//        super.onNewIntent(intent);
//
//        Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
//
//        if (tag != null) {
//            String[] techList = tag.getTechList();
//            textView.setText("Tag detected:\n" + Arrays.toString(techList));
//        }
//    }
//}
