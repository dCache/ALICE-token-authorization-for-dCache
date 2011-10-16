package org.dcache.xrootd.plugins.alice;

import java.util.Map;
import java.security.KeyPair;

/**
 * Identical to TokenAuthorization1 except that the token check and
 * path mapping is also applied to stat and statx requests.
 */
public class TokenAuthorization2 extends TokenAuthorization1
{
    public TokenAuthorization2(Map<String,KeyPair> keystore)
    {
        super(keystore);
    }

    @Override
    protected boolean skipCheck(int requestId)
    {
        return false;
    }
}
