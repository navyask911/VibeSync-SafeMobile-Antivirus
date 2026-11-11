package com.vibesync.antivirus.data.local
import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
@RunWith(AndroidJUnit4::class)
class QuarantineVaultDaoTest {
 private lateinit var db:ThreatDatabase
 @Before fun setUp(){db=Room.inMemoryDatabaseBuilder(ApplicationProvider.getApplicationContext<Context>(),ThreatDatabase::class.java).build()}
 @After fun tearDown(){db.close()}
 @Test fun metadataRoundTrips()=runBlocking {
  val entry=QuarantineVaultEntity("vault-id",1234L,"sample.apk","Downloads/sample.apk","a".repeat(64),null,"/private/quarantine/item.smq","local_sha256_match","QUARANTINED")
  db.quarantineVaultDao().insert(entry)
  assertEquals(entry,db.quarantineVaultDao().findById("vault-id"))
  assertEquals(listOf(entry),db.quarantineVaultDao().listRecent(10))
 }
}
