package com.vibesync.antivirus.test;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * Debug-build-only destination used by the encrypted quarantine instrumentation round-trip.
 * Java avoids coupling provider Binder callbacks to the instrumentation APK's Kotlin runtime.
 */
public final class RoundTripContentProvider extends ContentProvider {
    @Override
    public boolean onCreate() {
        return true;
    }

    @Override
    public String getType(Uri uri) {
        return "application/octet-stream";
    }

    @Override
    public Cursor query(
            Uri uri,
            String[] projection,
            String selection,
            String[] selectionArgs,
            String sortOrder
    ) {
        String[] columns = projection != null ? projection : new String[]{"_display_name"};
        MatrixCursor cursor = new MatrixCursor(columns);
        Object[] row = new Object[columns.length];
        for (int index = 0; index < columns.length; index++) {
            row[index] = "_display_name".equals(columns[index])
                    ? (uri.getLastPathSegment() != null ? uri.getLastPathSegment() : "restored-file")
                    : null;
        }
        cursor.addRow(row);
        return cursor;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        return 0;
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        return target(uri).delete() ? 1 : 0;
    }

    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        File file = target(uri);
        File parent = file.getParentFile();
        if (parent == null || (!parent.exists() && !parent.mkdirs() && !parent.isDirectory())) {
            throw new FileNotFoundException("Could not create the quarantine round-trip cache directory.");
        }
        int flags = mode != null && mode.contains("w")
                ? ParcelFileDescriptor.MODE_CREATE
                    | ParcelFileDescriptor.MODE_TRUNCATE
                    | ParcelFileDescriptor.MODE_WRITE_ONLY
                : ParcelFileDescriptor.MODE_READ_ONLY;
        return ParcelFileDescriptor.open(file, flags);
    }

    private File target(Uri uri) {
        String lastSegment = uri.getLastPathSegment();
        String safeName = (lastSegment != null ? lastSegment : "restored-file")
                .replaceAll("[^A-Za-z0-9_-]", "_");
        if (getContext() == null) {
            throw new IllegalStateException("Round-trip provider is not attached to a context.");
        }
        return new File(getContext().getCacheDir(), "safe-mobile-roundtrip-" + safeName);
    }
}
