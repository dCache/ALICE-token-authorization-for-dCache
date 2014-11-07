package org.dcache.xrootd.plugins.alice;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.Subject;
import javax.security.auth.login.CredentialException;

import java.io.File;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;

import org.dcache.xrootd.core.XrootdException;
import org.dcache.xrootd.plugins.AuthorizationHandler;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.protocol.XrootdProtocol.*;

import static com.google.common.base.Preconditions.checkNotNull;
import static org.dcache.xrootd.protocol.XrootdProtocol.*;

/**
 * The original Alice authentication scheme used in dCache.
 *
 * For unknown reasons the check and path mapping was not applied to
 * stat or statx requests. This has been resolved in
 * TokenAuthorization2.
 */
public class TokenAuthorization1 implements AuthorizationHandler
{
    private final Map<String,KeyPair> keystore;

    public TokenAuthorization1(Map<String,KeyPair> keystore)
    {
        this.keystore = checkNotNull(keystore);
    }

    @Override
    public String authorize(Subject subject,
                            InetSocketAddress localAddress,
                            InetSocketAddress remoteAddress,
                            String path,
                            Map<String, String> opaque,
                            int request,
                            FilePerm mode)
            throws XrootdException
    {
        if (path == null) {
            throw new IllegalArgumentException("The lfn string must not be null.");
        }

        String authzTokenString = opaque.get("authz");
        if (authzTokenString == null) {
            if (request == XrootdProtocol.kXR_stat ||
                request == XrootdProtocol.kXR_statx) {
                return path;
            }
            throw new XrootdException(kXR_NotAuthorized, "An authorization token is required for this request.");
        }

        // get the VO-specific keypair or the default keypair if VO
        // was not specified
        KeyPair keypair = getKeys(opaque.get("vo"));

        // decode the envelope from the token using the keypair
        // (Remote public key, local private key)
        Envelope env;
        try {
            env = decodeEnvelope(authzTokenString, keypair);
        } catch (CorruptedEnvelopeException | IllegalBlockSizeException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | SignatureException e) {
            throw new XrootdException(kXR_ArgInvalid, "Error parsing authorization token: " + e.getMessage());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new XrootdException(kXR_ServerError, "Error parsing authorization token: " + e.getMessage());
        } catch (CredentialException e) {
            throw new XrootdException(kXR_NotAuthorized, "Error parsing authorization token: " + e.getMessage());
        }

        // loop through all files contained in the envelope and find
        // the one with the matching lfn if no match is found, the
        // token/envelope is possibly hijacked
        Envelope.GridFile file = findFile(path, env);
        if (file == null) {
            throw new XrootdException(kXR_NotAuthorized, "Authorization token doesn't contain any file permissions for lfn " + path + ".");
        }

        // check for hostname:port in the TURL. Must match the current
        // xrootd service endpoint.  If this check fails, the token is
        // possibly hijacked
        if (!Arrays.equals(file.getTurlHost().getAddress(), localAddress.getAddress().getAddress())) {
            throw new XrootdException(kXR_NotAuthorized, "Hostname mismatch in authorization token (address=" + localAddress + " turl=" + file.getTurl() + ").");
        }

        int turlPort =
            (file.getTurlPort() == -1)
            ? XrootdProtocol.DEFAULT_PORT
            : file.getTurlPort();
        if (turlPort != localAddress.getPort()) {
            throw new XrootdException(kXR_NotAuthorized, "Port mismatch in authorization token (address=" + localAddress + " turl=" + file.getTurl() + ").");
        }


        // the authorization check. read access (lowest permission
        // required) is granted by default (file.getAccess() == 0), we
        // must check only in case of writing
        FilePerm grantedPermission = file.getAccess();
        if (mode == FilePerm.WRITE) {
            if (grantedPermission.ordinal() < FilePerm.WRITE_ONCE.ordinal()) {
                throw new XrootdException(kXR_NotAuthorized, "Token lacks authorization for requested operation.");
            }
        } else if (mode == FilePerm.DELETE) {
            if (grantedPermission.ordinal() < FilePerm.DELETE.ordinal()) {
                throw new XrootdException(kXR_NotAuthorized, "Token lacks authorization for requested operation.");
            }
        }

        return file.getTurlPath();
    }

    private Envelope.GridFile findFile(String path, Envelope env)
    {
        for (Envelope.GridFile file: env.getFiles()) {
            if (path.equals(file.getLfn())) {
                return file;
            }
        }
        return null;
    }

    private Envelope decodeEnvelope(String authzTokenString, KeyPair keypair)
            throws CorruptedEnvelopeException, NoSuchPaddingException, InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, SignatureException,
            NoSuchProviderException, InvalidKeyException, CredentialException
    {
        EncryptedAuthzToken token =
            new EncryptedAuthzToken(authzTokenString,
                                    (RSAPrivateKey) keypair.getPrivate(),
                                    (RSAPublicKey) keypair.getPublic());
        return new Envelope(token.decrypt());
    }

    private KeyPair getKeys(String vo) throws XrootdException
    {
        KeyPair keypair;
        if (vo != null) {
            keypair = keystore.get(vo);
            if (keypair == null) {
                throw new XrootdException(kXR_NotAuthorized, "VO " + vo + " is not authorized.");
            }
        } else {
            // fall back to default keypair in case the VO is
            // unspecified
            keypair = keystore.get("*");
            if (keypair == null) {
                throw new XrootdException(kXR_NotAuthorized, "No default VO configured in key store; VO is required.");
            }
        }
        return keypair;
    }

    public static void main(String[] args)
        throws Exception
    {
        TokenAuthorization1Factory factory =
            new TokenAuthorization1Factory(new File(args[0]));
        String token = args[1];
        TokenAuthorization1 handler = factory.createHandler();
        System.out.println(handler.decodeEnvelope(token, handler.getKeys(null)));
    }
}
