package im.status.keycard;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import im.status.keycard.KeycardApplet;
import im.status.keycard.applet.*;
import im.status.keycard.desktop.LedgerUSBManager;
import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardListener;
import im.status.keycard.Crypto;
import javacard.framework.AID;
import javacard.framework.ISO7816;

import org.bitcoinj.core.ECKey;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.*;
import org.web3j.crypto.*;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.request.RawTransaction;
import org.web3j.protocol.core.methods.response.EthSendTransaction;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.Transfer;
import org.web3j.utils.Convert;
import org.web3j.utils.Numeric;

import org.bouncycastle.jce.interfaces.ECPublicKey;

import javax.smartcardio.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Random;

import static org.apache.commons.codec.digest.DigestUtils.sha256;
import static org.junit.jupiter.api.Assertions.*;


@DisplayName("Stress Test the Keycard Applet")
public class KeycardStressTest {
  // Psiring key is KeycardTest
  private static CardTerminal cardTerminal;
  private static CardChannel apduChannel;
  private static im.status.keycard.io.CardChannel sdkChannel;
  private static CardSimulator simulator;

  private static LedgerUSBManager usbManager;

  private static byte[] sharedSecret;

  private TestSecureChannelSession secureChannel;
  private TestKeycardCommandSet cmdSet;

  private static final int TARGET_SIMULATOR = 0;
  private static final int TARGET_CARD = 1;
  private static final int TARGET_LEDGERUSB = 2;

  private static final int TARGET;
  private static final int success = ISO7816.SW_NO_ERROR & 0xffff;

  APDUResponse response;

  static {
    switch(System.getProperty("im.status.keycard.test.target", "card")) {
      case "simulator":
        TARGET = TARGET_SIMULATOR;
        break;
      case "card":
        TARGET = TARGET_CARD;
        break;
      case "ledgerusb":
        TARGET = TARGET_LEDGERUSB;
        break;
      default:
        throw new RuntimeException("Unknown target");
    }
  }

  @BeforeAll
  static void initAll() throws Exception {
    switch(TARGET) {
      case TARGET_SIMULATOR:
        openSimulatorChannel();
        break;
      case TARGET_CARD:
        openCardChannel();
        break;
      case TARGET_LEDGERUSB:
        openLedgerUSBChannel();
        break;
      default:
        throw new IllegalStateException("Unknown target");
    }

    initIfNeeded();
  }

  private static void initCapabilities(ApplicationInfo info) {
    HashSet<String> capabilities = new HashSet<>();

    if (info.hasSecureChannelCapability()) {
      capabilities.add("secureChannel");
    }

    if (info.hasCredentialsManagementCapability()) {
      capabilities.add("credentialsManagement");
    }

    if (info.hasKeyManagementCapability()) {
      capabilities.add("keyManagement");
    }

    if (info.hasNDEFCapability()) {
      capabilities.add("ndef");
    }

    CapabilityCondition.availableCapabilities = capabilities;
  }

  private static void openSimulatorChannel() throws Exception {
    simulator = new CardSimulator();
    AID appletAID = AIDUtil.create(Identifiers.getKeycardInstanceAID());
    simulator.installApplet(appletAID, KeycardApplet.class);
    cardTerminal = CardTerminalSimulator.terminal(simulator);

    openPCSCChannel();
  }

  private static void openCardChannel() throws Exception {
    TerminalFactory tf = TerminalFactory.getDefault();

    for (CardTerminal t : tf.terminals().list()) {
      if (t.isCardPresent()) {
        cardTerminal = t;
        break;
      }
    }

    openPCSCChannel();
  }

  private static void openPCSCChannel() throws Exception {
    Card apduCard = cardTerminal.connect("*");
    apduChannel = apduCard.getBasicChannel();
    sdkChannel = new PCSCCardChannel(apduChannel);
  }

  private static void openLedgerUSBChannel() {
    usbManager = new LedgerUSBManager(new CardListener() {
      @Override
      public void onConnected(im.status.keycard.io.CardChannel channel) {
        sdkChannel = channel;
      }

      @Override
      public void onDisconnected() {
        throw new RuntimeException("Ledger was disconnected during test run!");
      }
    });

    usbManager.start();
  }

  private static void initIfNeeded() throws Exception {
    KeycardCommandSet cmdSet = new KeycardCommandSet(sdkChannel);
    byte[] data = cmdSet.select().checkOK().getData();

    initCapabilities(cmdSet.getApplicationInfo());

    sharedSecret = cmdSet.pairingPasswordToSecret(System.getProperty("im.status.keycard.test.pairing", "KeycardTest"));

    if (!cmdSet.getApplicationInfo().isInitializedCard()) {
      assertEquals(0x9000, cmdSet.init("000000", "123456789012", sharedSecret).getSw());
    }
  }

  @BeforeEach
  void init() throws Exception {
    reset();
    cmdSet = new TestKeycardCommandSet(sdkChannel);
    secureChannel = new TestSecureChannelSession();
    cmdSet.setSecureChannel(secureChannel);
    cmdSet.select().checkOK();

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoPair(sharedSecret);
    }
  }

  private void reset() {
    switch(TARGET) {
      case TARGET_SIMULATOR:
        simulator.reset();
        break;
      case TARGET_CARD:
        apduChannel.getCard().getATR();
        break;
      default:
        break;
    }
  }

  
  private void resetAndSelectAndOpenSC() throws Exception {
    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      reset();
      cmdSet.select();
      cmdSet.autoOpenSecureChannel();
    }
  }

  @AfterEach
  void tearDown() throws Exception {
    resetAndSelectAndOpenSC();

    if (cmdSet.getApplicationInfo().hasCredentialsManagementCapability()) {
      APDUResponse response = cmdSet.verifyPIN("000000");
      assertEquals(0x9000, response.getSw());
    }

    if (cmdSet.getApplicationInfo().hasSecureChannelCapability()) {
      cmdSet.autoUnpair();
    }
  }

  @AfterAll
  static void tearDownAll() {
    if (usbManager != null) {
      usbManager.stop();
    }
  }

  @Test
  @DisplayName("Run tests")
  void tests() throws Exception {
    cmdSet.autoOpenSecureChannel();
    response = cmdSet.verifyPIN("000000");
    assertEquals(success, response.getSw());
    
    // Load a cert

    // Run the stress test
    runTest(15, 50);
  }


  private void runTest(int outerIter, int innerIter) throws Exception {
    Random random = new Random();
    byte[] preImage = new byte[20];
    byte[] hash = new byte[32];
    // Do this `n` times:
    for (int n = 0; n < outerIter; n++) {
      System.out.println(n);

      // 1. Generate seed on card (non-exportable)
      byte empty = (byte) 0;
      byte flag = (byte) 0;
      response = cmdSet.sendSecureCommand(KeycardApplet.INS_GENERATE_KEY, flag, empty, new byte[0]);
      assertEquals(success, response.getSw());
      
      // 2. Generate 100 random derivation trees. Request pubkeys. Request sigs.
      //      Verify sigs against pubkeys.
      int[] indices;
      byte[] path;
      byte[] pubKey;
      
      for (short i = 0; i < innerIter; i++) {
        // Load the preimage with data
        random.nextBytes(preImage);
        hash = sha256(preImage);
        
        // Generate a random derivation path
        indices = getRandomPathIndices();
        path = getPath(indices);
        // Derive and export the pubkey
        response = cmdSet.sendSecureCommand(
          KeycardApplet.INS_EXPORT_KEY,
          KeycardApplet.EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT,
        KeycardApplet.EXPORT_KEY_P2_PUBLIC_AND_CHAINCODE,
        path
        );
        assertEquals(success, response.getSw());
        // Get the returned pubkey from the response
        pubKey = extractPublicKeyFromDerivation(response.getData());
        // TODO: Derive the key using the chaincode
        // The key derived here is what should actually be passed to verifySignResp
        
        // Request signature
        response = cmdSet.sign(hash);
        verifySignResp(preImage, pubKey, response);
      }
      
      // 3. Delete generated seed
      response = cmdSet.removeKey();
      assertEquals(success, response.getSw());
      
      // 4. Generate a seed here and load it
      byte[] seed = newSeed();
      response = cmdSet.sendSecureCommand(KeycardApplet.INS_LOAD_KEY, KeycardApplet.LOAD_KEY_P1_SEED, flag, seed);
      assertEquals(success, response.getSw());
      
      // 5. Generate 100 random derivaiton trees. Request pubkeys and compare against
      //      expected ones. Request sigs. Verify sigs against pubkeys.
      for (short i = 0; i < innerIter; i++) {
        // Load the preimage with data
        random.nextBytes(preImage);
        hash = sha256(preImage);
        
        // Generate a random derivation path
        indices = getRandomPathIndices();
        path = getPath(indices);
        
        // Derive and export the pubkey
        response = cmdSet.sendSecureCommand(
          KeycardApplet.INS_EXPORT_KEY,
          KeycardApplet.EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT,
          KeycardApplet.EXPORT_KEY_P2_PUBLIC_AND_CHAINCODE,
          path
        );
        assertEquals(success, response.getSw());
        // Get the returned pubkey from the response
        pubKey = extractPublicKeyFromDerivation(response.getData());
        // Verify this pubkey against the one derived here
        verifyPub(seed, indices, pubKey);
        // Request signature
        response = cmdSet.sign(hash);
        verifySignResp(preImage, pubKey, response);
      }

      // 6. Delete seed
      response = cmdSet.removeKey();
      assertEquals(success, response.getSw());
      
      // 7. Request 100 sigs from the cert key and verify.
      
      // 8. Load 100 seeds, get a random pubkey, and request a signature against it.
      //      Verify the sig.
      for (short i = 0; i < innerIter; i ++) {
        // Load seed
        seed = newSeed();
        response = cmdSet.sendSecureCommand(KeycardApplet.INS_LOAD_KEY, KeycardApplet.LOAD_KEY_P1_SEED, flag, seed);
        assertEquals(success, response.getSw());
        
        // Get a pubKey path
        // Load the preimage with data
        random.nextBytes(preImage);
        hash = sha256(preImage);
        
        // Generate a random derivation path
        indices = getRandomPathIndices();
        path = getPath(indices);
        
        // Derive and export the pubkey
        response = cmdSet.sendSecureCommand(
          KeycardApplet.INS_EXPORT_KEY,
          KeycardApplet.EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT,
          KeycardApplet.EXPORT_KEY_P2_PUBLIC_AND_CHAINCODE,
          path
        );
        assertEquals(success, response.getSw());
        // Get the returned pubkey from the response
        pubKey = extractPublicKeyFromDerivation(response.getData());
        // Verify this pubkey against the one derived here
        verifyPub(seed, indices, pubKey);
        // Request signature
        response = cmdSet.sign(hash);
        verifySignResp(preImage, pubKey, response);
        
        // Delete seed
        response = cmdSet.removeKey();
        assertEquals(success, response.getSw());
      }
    }
  }




  private byte[] newSeed() {
    byte[] seed = new byte[KeycardApplet.BIP39_SEED_SIZE];
    Random random = new Random();
    random.nextBytes(seed);
    return seed;
  }

  private void verifyPub(byte[] seed, int[] indices, byte[] pubKey) {
    // Get private key
    DeterministicKey masterPriv = HDKeyDerivation.createMasterPrivateKey(seed);
    // Derive first index (44')
    ChildNumber ch = new ChildNumber(44, true);
    DeterministicKey priv = HDKeyDerivation.deriveChildKey(masterPriv, ch);
    // Derive subsequent indices
    boolean hardened;
    for (short i = 0; i < indices.length/2; i++) {
      hardened = indices[2*i+1] == 1 ? true : false;
      ch = new ChildNumber(indices[2*i], hardened);
      priv = HDKeyDerivation.deriveChildKey(priv, ch);
    }
    // Convert final child priv to pub and return
    byte[] expectedPubKey = priv.decompress().getPubKey();
    assertTrue(Arrays.equals(expectedPubKey, pubKey));
  }

  private int[] getRandomPathIndices() {
    Random r = new Random();
    short n = 4;
    int range = 100000;
    int[] path = new int[2*n]; // 4 indices and 4 hardened/not indicators
    for (short i = 0; i < n; i++) {
      path[2*i] = r.nextInt(range);
      path[2*i+1] = path[2*i] > range/2 ? 1 : 0;  // Assign hardended flag randomly
    }
    return path;
  }

  // Get a path to send to the device based on this set of indices
  // The indices are of format [a, aIsHardened, b, bIsHardened, ...]
  private byte[] getPath(int[] indices) {
    int n = indices.length;
    String path = "m/44'";
    for (short i = 0; i < n/2; i++) {
      path += String.format("/%d", indices[2*i]);
      if (indices[2*i+1] == 1) {
        // Add hardened indication
        path += "'";
      }
    }
    KeyPath kp = new KeyPath(path);
    return kp.getData();
  }

  private boolean isMalleable(byte[] sig) {
    int rLen = sig[3];
    int sOff = 6 + rLen;
    int sLen = sig.length - rLen - 6;

    BigInteger s = new BigInteger(Arrays.copyOfRange(sig, sOff, sOff + sLen));
    BigInteger limit = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0", 16);

    return s.compareTo(limit) >= 1;
  }

  private byte[] extractPublicKeyFromDerivation(byte[] data) {
    assertEquals(data[0], KeycardApplet.TLV_KEY_TEMPLATE);
    assertEquals(data[1], 4 + Crypto.KEY_PUB_SIZE + KeycardApplet.CHAIN_CODE_SIZE);
    assertEquals(data[2], KeycardApplet.TLV_PUB_KEY);
    assertEquals(data[3], Crypto.KEY_PUB_SIZE);
    int off = 4;
    return Arrays.copyOfRange(data, off, off + Crypto.KEY_PUB_SIZE);
  }

  private byte[] extractPublicKeyFromSignature(byte[] sig) {
    assertEquals(KeycardApplet.TLV_SIGNATURE_TEMPLATE, sig[0]);
    assertEquals((byte) 0x81, sig[1]);
    assertEquals(KeycardApplet.TLV_PUB_KEY, sig[3]);

    return Arrays.copyOfRange(sig, 5, 5 + sig[4]);
  }
  
  private byte[] extractSignature(byte[] sig) {
    int off = sig[4] + 5;
    return Arrays.copyOfRange(sig, off, off + sig[off + 1] + 2);
  }

  private void verifySignResp(byte[] preImage, byte[] expectedPubKey, APDUResponse response) throws Exception {
    Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
    assertEquals(0x9000, response.getSw());
    byte[] sig = response.getData();
    byte[] pubKey = extractPublicKeyFromSignature(sig);
    assertTrue(Arrays.equals(pubKey, expectedPubKey));
    sig = extractSignature(sig);

    // Verify the signature against the pubkey
    ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(pubKey), ecSpec);
    ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

    signature.initVerify(cardKey);
    assertEquals((SecureChannel.SC_KEY_LENGTH * 2 / 8) + 1, pubKey.length);    
    signature.update(preImage);
    try {
      assertTrue(signature.verify(sig));
    } catch (java.security.SignatureException e) {
      System.out.println("Error verifying signature");
      System.out.println(e);
      System.out.println("PubKey used:     " + Arrays.toString(pubKey));
      System.out.println("PreImage used:   " + Arrays.toString(preImage));
      System.out.println("Signature bytes: " + Arrays.toString(sig));
    }
    assertFalse(isMalleable(sig));
  }

}
