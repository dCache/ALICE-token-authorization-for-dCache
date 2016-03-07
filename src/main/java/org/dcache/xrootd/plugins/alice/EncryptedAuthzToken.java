package org.dcache.xrootd.plugins.alice;

import java.io.IOException;
import java.io.LineNumberReader;
import java.io.StringReader;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Stack;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.base.Throwables;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This class does the decoding/decryption of a given authorization token which has to apply to the follwing
 * format:
 *
 * -----BEGIN SEALED CIPHER-----
 * ..
 * .. (Base64-encoded cipher)
 * ..
 * -----END SEALED CIPHER-----
 * -----BEGIN SEALED ENVELOPE-----
 * ..
 * .. (Base64-encoded envelope)
 * ..
 * -----END SEALED ENVELOPE-----
 *
 * The result is an authorization token object.
 *
 *
 * @author Martin Radicke
 *
 */
public class EncryptedAuthzToken {
    //	static Logger logger = LoggerFactory.getLogger(EncryptedAuthzToken.class);

    //	delimiters used to split the raw token into Cipher and Sealed Envelope
    private final static String CYPHER_START = "-----BEGIN SEALED CIPHER-----";
    private final static String CYPHER_END = "-----END SEALED CIPHER-----";
    private final static String ENVELOPE_START = "-----BEGIN SEALED ENVELOPE-----";
    private final static String ENVELOPE_END = "-----END SEALED ENVELOPE-----";

    //	Blowfish initialisation vector
    private final static byte[] BLOWFISH_IV = "$KJh#(}q".getBytes();

    //	raw cipher and Sealed Envelope
    private StringBuffer cipherEncryptedBase64;
    private StringBuffer envelopeEncryptedBase64;

    //	decrypted blowfish key
    private byte[] symmetricKey;

    //	extracted SHA1-signature to verify envelope data
    private byte[] signature;

    //	the envelope data itself (token payload)
    private byte[] envelope;

    //	local private key
    private RSAPrivateKey privKey;

    //	remote (e.g. from the file catalogue) public key
    private RSAPublicKey pubKey;

    static
    {
        // the security provider used for decryption/verification
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Creates a new decryption instance.
     *
     * @param rawToken rawToken the sealed token which is going to be decrypted
     * @param privKey  the local private RSA key
     * @param pubKey the remote public RSA key
     */
    public EncryptedAuthzToken(String rawToken, RSAPrivateKey privKey, RSAPublicKey pubKey) throws CorruptedEnvelopeException
    {
        this.privKey = privKey;
        this.pubKey = pubKey;
        splitToken(rawToken);
    }

    /**
     * Does the actual decryption/decoding of the raw token. This
     * method should not be called for more than one times.
     *
     * @return the decrypted envelope or NULL if signature could not be verified
     */
    public String decrypt() throws NoSuchProviderException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, SignatureException
    {
        // get RSA-sealed cipher (aka session- or symmetric key(
        decryptSealedCipher();

        // decrypt signature and envelope with symmetric key using Blowfish
        decryptSealedEnvelope();

        // verify envelope using the signature
        if (!verifyEnvelope()) {
            return null;
        }

        return new String(envelope);
    }

    /**
     * Decrypts the first component of the sealed token, which
     * contains the session key (aka symmetric key).
     */
    private void decryptSealedCipher() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException
    {
        // decode base64
        byte[] encryptedCipher = Base64.decode(cipherEncryptedBase64.toString());

        // RSA-decrypt the session key by using the local private key
        Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding","BC");
        cipher.init(Cipher.UNWRAP_MODE, privKey);

        symmetricKey = cipher.unwrap(encryptedCipher,"Blowfish",Cipher.SECRET_KEY).getEncoded();
    }

    /**
     * Decrypts the actual envelope (the 2nd component) using the
     * symmetric key and extracts the signature.
     *
     * @throws GeneralSecurityException
     */
    private void decryptSealedEnvelope() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException
    {
        // Base64-decode envelope
        byte[] encryptedEnvelope =
            Base64.decode(envelopeEncryptedBase64.toString());

        // envelope format:
        // ================
        // 1. signature_length[4]			!! integer in big endian (network byte order)
        // 2. signature[signature_length]		!! RSA-privately encypted SHA1-hash of envelope_data
        // 3. envelope_data[encryptedEnvelope.length - signature_length - 4]		!! the payload of the token, Blowfish-encrypted

        // usually big endian, but for legacy reasons little endian
        // for now (going to be changed in next Alien file catalogue
        // version

        // big endian
        int signatureLength = encryptedEnvelope[0] & 0xff << 24 | encryptedEnvelope[1] & 0xff << 16 | encryptedEnvelope[2] & 0xff <<  8 | encryptedEnvelope[3] & 0xff;
        // int signatureLength = encryptedEnvelope[0] & 0xff | encryptedEnvelope[1] & 0xff << 8 | encryptedEnvelope[2] & 0xff <<  16 | encryptedEnvelope[3] & 0xff << 24;
        int envelopeOffset = 4 + signatureLength;

        // store signature into a seperate buffer
        signature = new byte[signatureLength];
        System.arraycopy(encryptedEnvelope, 4, signature, 0, signatureLength);

        // stripe off trailing zero (the key is stored as a
        // zero-padded array for easier string handling in C)
        int keylen = symmetricKey.length - 1;

        //////////////////////////////////////////////
        // BC Blowfish, native interface
        //////////////////////////////////////////////

        // CipherParameters params = new ParametersWithIV(new KeyParameter(symmetricKey,0,keylen), iv);
        // CBCBlockCipher bc = new CBCBlockCipher(new BlowfishEngine());
        // bc.init(false, params);
        //
        // byte[] unencrypted = new byte[encryptedEnvelope.length-envelopeOffset];
        //
        // for (int i = 0;i<encryptedEnvelope.length-envelopeOffset;i=i+8) {
        //     bc.processBlock(encryptedEnvelope, envelopeOffset+i, unencrypted, i);
        // }
        //
        // printArray("decrypted env", unencrypted, 0, unencrypted.length);


        //////////////////////////////////////////////
        // SunJCE/BC Blowfish
        //////////////////////////////////////////////
        SecretKeySpec symKeySpec =
            new SecretKeySpec(symmetricKey, 0, keylen, "Blowfish");

        // SunJCE Provider doing blowfish decrypt (how about performance?)
        // cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding","SunJCE");

        // BC provider doing blowfish decryption
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding","BC");
        cipher.init(Cipher.DECRYPT_MODE, symKeySpec, new IvParameterSpec(BLOWFISH_IV));
        envelope = cipher.doFinal(encryptedEnvelope, envelopeOffset, encryptedEnvelope.length - envelopeOffset);

        //////////////////////////////////////////////
        // BlowfishJ (does not work because the lack of Padding)
        //////////////////////////////////////////////

        // BlowfishCBC bfc = new BlowfishCBC(key3,0,key3.length, new BigInteger(iv).longValue());
        //
        // if (bfc.weakKeyCheck())
        // {
        //     logger.debug("CBC key is weak!");
        // }
        // else
        // {
        //     logger.debug("CBC key OK");
        // }
        //
        // logger.debug(encryptedEnvelope.length+" "+envelopeOffset+" "+(encryptedEnvelope.length-envelopeOffset));
        // bfc.decrypt(encryptedEnvelope, envelopeOffset, unencrypted, 0, encryptedEnvelope.length - envelopeOffset);
        //
        // printArray("decrypted env", unencrypted, 0, unencrypted.length);
        // logger.debug("decrypted cleartext:\n"+new String(unencrypted));
    }

    /**
     * Verifies the authenticity of the envelope by comparing the SHA1
     * hash of the envlope with the signature
     *
     * @return true after successful verification
     */
    private boolean verifyEnvelope() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        Signature signer = Signature.getInstance("SHA1withRSA","BC");
        signer.initVerify(pubKey);
        signer.update(envelope);
        return signer.verify(signature);
    }

    /**
     * Splits the raw token (see class description for format) into
     * its two components cipher and envelope
     *
     * @param rawToken the token which is going to be splitted
     */
    private void splitToken(String rawToken) throws CorruptedEnvelopeException
    {
        cipherEncryptedBase64 = new StringBuffer();
        envelopeEncryptedBase64 = new StringBuffer();

        Stack stack = new Stack();

        LineNumberReader input =
            new LineNumberReader(new StringReader(rawToken));

        try {
            String line;
            while ((line = input.readLine()) != null) {
                if (line.equals(CYPHER_START)) {
                    stack.push(CYPHER_START);
                    continue;
                }

                if (line.equals(CYPHER_END)) {
                    if (!stack.peek().equals(CYPHER_START)) {
                        throw new CorruptedEnvelopeException("Illegal format: Cannot parse encrypted cipher");
                    }
                    stack.pop();
                    continue;
                }

                if (line.equals(ENVELOPE_START)) {
                    // check if ENVELOPE part is not nested in CYPHER part
                    if (!stack.isEmpty()) {
                        throw new CorruptedEnvelopeException("Illegal format: Cannot parse encrypted envelope");
                    }
                    stack.push(ENVELOPE_START);
                    continue;
                }

                if (line.equals(ENVELOPE_END)) {
                    if (!stack.peek().equals(ENVELOPE_START)) {
                        throw new CorruptedEnvelopeException("Illegal format: Cannot parse encrypted envelope");
                    }
                    stack.pop();
                    continue;
                }

                if (stack.isEmpty()) {
                    continue;
                }

                if (stack.peek().equals(CYPHER_START)) {
                    cipherEncryptedBase64.append(line);
                    continue;
                }

                if (stack.peek().equals(ENVELOPE_START)) {
                    envelopeEncryptedBase64.append(line);
                    continue;
                }
            }

        } catch (IOException e) {
            Throwables.propagate(e);
        }
    }

    /**
     * Helper method to print out anarray in hex notation.
     * @param name the name to prefix the hex dump
     * @param array the array which will be dumped
     * @param offset the offset from where the dump will start
     * @param len the number of bytes to be dumped
     */
    private String arrayToHex(String name, byte[] array, int offset, int len)
    {
        if (array == null) {
            return "";
        }

        StringBuilder sb = new StringBuilder(name + ": ");
        for (int i = offset; i < offset + len;i++) {
            String s = Integer.toHexString(array[i] & 0xff);
            if (s.length() == 1) {
                sb.append("0");
            }
            sb.append(s.toUpperCase());
        }

        sb.append(" (total:");
        sb.append(len);
        sb.append(" bytes)");

        return sb.toString();
    }
}
