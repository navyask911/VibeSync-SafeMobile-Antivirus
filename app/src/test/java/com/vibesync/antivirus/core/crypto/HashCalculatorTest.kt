package com.vibesync.antivirus.core.crypto

import com.vibesync.antivirus.core.engine.hash.HashMatcher
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class HashCalculatorTest {
 @Test fun hashesAbcCorrectly() {
  val result=HashCalculator().calculate(ByteArrayInputStream("abc".toByteArray()))
  assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",result.sha256)
  assertEquals("900150983cd24fb0d6963f7d28e17f72",result.md5)
  assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d",result.sha1)
  assertEquals(3L,result.bytesRead)
 }
 @Test fun hashesEmptyInputCorrectly() {
  val result=HashCalculator().calculate(ByteArrayInputStream(byteArrayOf()))
  assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",result.sha256)
  assertEquals("d41d8cd98f00b204e9800998ecf8427e",result.md5)
  assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709",result.sha1)
  assertEquals(0L,result.bytesRead)
 }
 @Test fun eicarTestSignatureIsPinnedAsSha256Only() {
  assertEquals("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", HashMatcher.EICAR_SHA256)
  assertEquals(64, HashMatcher.EICAR_SHA256.length)
  assertTrue(HashMatcher.EICAR_SHA256.all { it in "0123456789abcdef" })
 }
}
