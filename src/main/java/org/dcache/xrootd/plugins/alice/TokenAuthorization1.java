package org.dcache.xrootd.plugins.alice;

import java.security.GeneralSecurityException;
import java.security.AccessControlException;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Map;
import java.io.File;
import java.net.InetSocketAddress;

import javax.security.auth.Subject;
import org.dcache.xrootd.protocol.XrootdProtocol;
import org.dcache.xrootd.protocol.XrootdProtocol.FilePerm;
import org.dcache.xrootd.plugins.AuthorizationHandler;

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
        this.keystore = keystore;
    }

    @Override
    public String authorize(Subject subject,
                            InetSocketAddress localAddress,
                            InetSocketAddress remoteAddress,
                            String path,
                            Map<String, String> opaque,
                            int request,
                            FilePerm mode)
            throws SecurityException, GeneralSecurityException
    {
        if (path == null) {
            throw new IllegalArgumentException("the lfn string must not be null");
        }

        String authzTokenString = opaque.get("authz");
        if (authzTokenString == null) {
            if (request == XrootdProtocol.kXR_stat ||
                request == XrootdProtocol.kXR_statx) {
                return path;
            }
            throw new GeneralSecurityException("No authorization token found in open request, access denied.");
        }

        // get the VO-specific keypair or the default keypair if VO
        // was not specified
        KeyPair keypair = getKeys((String) opaque.get("vo"));

        // decode the envelope from the token using the keypair
        // (Remote publicm key, local private key)
        Envelope env;
        try {
            env = decodeEnvelope(authzTokenString, keypair);
        } catch (CorruptedEnvelopeException e) {
            throw new GeneralSecurityException("Error parsing authorization token: "+e.getMessage());
        }

        // loop through all files contained in the envelope and find
        // the one with the matching lfn if no match is found, the
        // token/envelope is possibly hijacked
        Envelope.GridFile file = findFile(path, env);
        if (file == null) {
            throw new GeneralSecurityException("authorization token doesn't contain any file permissions for lfn " + path);
        }

        // check for hostname:port in the TURL. Must match the current
        // xrootd service endpoint.  If this check fails, the token is
        // possibly hijacked
        if (!Arrays.equals(file.getTurlHost().getAddress(),
                           localAddress.getAddress().getAddress())) {
            throw new GeneralSecurityException("Hostname mismatch in authorization token (lfn="+file.getLfn()+" TURL="+file.getTurl()+")");
        }

        int turlPort =
            (file.getTurlPort() == -1)
            ? XrootdProtocol.DEFAULT_PORT
            : file.getTurlPort();
        if (turlPort != localAddress.getPort()) {
            throw new GeneralSecurityException("Port mismatch in authorization token (lfn="+file.getLfn()+" TURL="+file.getTurl()+")");
        }


        // the authorization check. read access (lowest permission
        // required) is granted by default (file.getAccess() == 0), we
        // must check only in case of writing
        int grantedPermission = file.getAccess();
        if (mode == FilePerm.WRITE) {
            if (grantedPermission < FilePerm.WRITE_ONCE.ordinal()) {
                throw new AccessControlException("Token lacks authorization for requested operation");
            }
        } else if (mode == FilePerm.DELETE) {
            if (grantedPermission < FilePerm.DELETE.ordinal()) {
                throw new AccessControlException("Token lacks authorization for requested operation");
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
        throws GeneralSecurityException, CorruptedEnvelopeException
    {
        EncryptedAuthzToken token =
            new EncryptedAuthzToken(authzTokenString,
                                    (RSAPrivateKey) keypair.getPrivate(),
                                    (RSAPublicKey) keypair.getPublic());
        token.decrypt();
        return token.getEnvelope();
    }

    private KeyPair getKeys(String vo) throws GeneralSecurityException
    {
        if (keystore == null) {
            throw new GeneralSecurityException("no keystore found");
        }

        KeyPair keypair;
        if (vo != null) {
            if (keystore.containsKey(vo)) {
                keypair = keystore.get(vo);
            } else {
                throw new GeneralSecurityException("no keypair for VO "+vo+" found in keystore");
            }
        } else {
            // fall back to default keypair in case the VO is
            // unspecified
            if (keystore.containsKey("*")) {
                keypair = keystore.get("*");
            } else {
                throw new GeneralSecurityException("no default keypair found in keystore, required for decoding authorization token");
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
