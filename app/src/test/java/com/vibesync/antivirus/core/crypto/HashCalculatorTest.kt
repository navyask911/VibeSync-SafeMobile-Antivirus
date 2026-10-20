package com.vibesync.antivirus.core.crypto
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream
class HashCalculatorTest {
 @Test fun hashesAbcCorrectly() {
  val result = HashCalculator().calculate(ByteArrayInputStream("abc".toByteArray()))
  assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",result.sha256)
  assertEquals("900150983cd24fb0d6963f7d28e17f72",result.md5)
  assertEquals(3L,result.bytesRead)
 }
 @Test fun hashesEmptyInputCorrectly() {
  val result = HashCalculator().calculate(ByteArrayInputStream(byteArrayOf()))
  assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",result.sha256)
  assertEquals("d41d8cd98f00b204e9800998ecf8427e",result.md5)
  assertEquals(0L,result.bytesRead)
 }
}
