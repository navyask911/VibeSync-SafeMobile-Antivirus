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
 @Test fun standardEicarTestVectorHashesCorrectly() {
  val marker = "X5O!P%@AP[4\\\\PZX54(P^)7CC)7}\\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\\$H+H*"
  val result = HashCalculator().calculate(ByteArrayInputStream(marker.toByteArray(Charsets.US_ASCII)))
  assertEquals("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", result.sha256)
  assertEquals("44d88612fea8a8f36de82e1278abb02f", result.md5)
  assertEquals(68L, result.bytesRead)
 }
}
