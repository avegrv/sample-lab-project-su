package com.su.lab;

import android.Manifest;
import android.app.Activity;
import android.app.LoaderManager;
import android.content.CursorLoader;
import android.content.Intent;
import android.content.Loader;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.view.View;
import android.widget.AdapterView;
import android.widget.CursorAdapter;
import android.widget.ListView;
import android.widget.SimpleCursorAdapter;

import androidx.core.content.ContextCompat;

public class MainActivity extends Activity implements LoaderManager.LoaderCallbacks<Cursor>, AdapterView.OnItemClickListener {

    private final static String[] FROM_COLUMNS = {
            ContactsContract.Contacts.DISPLAY_NAME_PRIMARY
    };

    private static final String[] PROJECTION = {
            ContactsContract.Contacts._ID,
            ContactsContract.Contacts.LOOKUP_KEY,
            ContactsContract.Contacts.DISPLAY_NAME_PRIMARY
    };

    private final static int[] TO_IDS = {
            android.R.id.text1
    };

    private ListView contactsList;

    private CursorAdapter cursorAdapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        checkReadContactsPermission();
    }

    private void checkReadContactsPermission() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_CONTACTS) == PackageManager.PERMISSION_GRANTED) {
            readContacts();
        } else {
            requestPermissions( new String[]{Manifest.permission.READ_CONTACTS},  0);
        }
    }

    private void readContacts() {
        contactsList = findViewById(R.id.contact_list_view);
        // Gets a CursorAdapter
        cursorAdapter = new SimpleCursorAdapter(
                this,
                R.layout.contacts_list_item,
                null,
                FROM_COLUMNS,
                TO_IDS,
                0);
        // Sets the adapter for the ListView
        contactsList.setAdapter(cursorAdapter);

        getLoaderManager().initLoader(0, null, this);

        contactsList.setOnItemClickListener(this);
    }

    @Override
    public Loader<Cursor> onCreateLoader(int i, Bundle bundle) {
        // Starts the query
        return new CursorLoader(
                this,
                ContactsContract.Contacts.CONTENT_URI,
                PROJECTION,
                null,
                null,
                null
        );
    }

    @Override
    public void onLoadFinished(Loader<Cursor> loader, Cursor cursor) {
        cursorAdapter.swapCursor(cursor);
    }

    @Override
    public void onLoaderReset(Loader<Cursor> loader) {
        cursorAdapter.swapCursor(null);
    }

    @Override
    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
        Cursor cursor = cursorAdapter.getCursor();
        cursor.moveToPosition(position);
        long contactId = cursor.getLong(cursor.getColumnIndex(ContactsContract.Contacts._ID));
        openDetailsActivity(contactId);
    }

    private void openDetailsActivity(long contactId) {
        Intent intent = new Intent(this, DetailsActivity.class);
        intent.putExtra(DetailsActivity.CONTACT_ID_EXTRA,contactId);
        startActivity(intent);
    }
}