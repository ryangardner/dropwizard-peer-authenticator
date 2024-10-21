package com.washingtonpost.dw.auth;

import com.codahale.metrics.MetricRegistry;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.benmanes.caffeine.cache.CaffeineSpec;
import com.google.common.base.Preconditions;
import static com.washingtonpost.dw.auth.AllowedPeerConfiguration.Encryptor.NONE;
import com.washingtonpost.dw.auth.dao.FlatFilePeerDAO;
import com.washingtonpost.dw.auth.dao.StringPeerDAO;
import com.washingtonpost.dw.auth.model.Peer;
import io.dropwizard.auth.AuthDynamicFeature;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.Authorizer;
import io.dropwizard.auth.CachingAuthenticator;
import io.dropwizard.auth.PermitAllAuthorizer;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.auth.basic.BasicCredentials;
import io.dropwizard.core.setup.Environment;
import java.io.InputStream;
import org.glassfish.jersey.server.filter.RolesAllowedDynamicFeature;
import org.jasypt.util.password.BasicPasswordEncryptor;
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;

/**
 * <p>Container for configuration, in the "config + factory" pattern that DropWizard likes</p>
 * <p>This configuration can behave in a couple different ways, depending on what properties are set:</p>
 * <ol>
 *   <li>If a "credentialFile" is specified (i.e. non-null), the usernames and passwords of the allowed peers will be read
 * from that file</li>
 *   <li>If instead the "users" and "passwords" strings are specified (i.e. non-null), then those strings are split up
 * with whatever value is specified by the "delimited" property and the token (user, password)s are used as the list of
 * allowed peers.  By default, the delimiter is ";", so if {@code users="bob;alice"} and {@code passwords="foo;bar"} then
 * the list of allowed peers would contain "user bob with password foo" and "user alice with password bar"</li>
 * </ol>
 * <p>If a cachePolicy is set, then the Authenticator that is registered with Jersey upon calling {@code registerAuthenticator}
 * will be a CachingAuthenticator.  Otherwise, it'll be an instance of {@code AllowedPeerAuthenticator}</p>
 */
public class AllowedPeerConfiguration {

    @JsonProperty("realm")
    private String realm = "peers";

    @JsonProperty("caffeineSpec")
    private CaffeineSpec caffeineSpec;

    @JsonProperty("credentialFile")
    private String credentialFile;

    @JsonProperty("users")
    private String users;

    @JsonProperty("passwords")
    private String passwords;

    @JsonProperty("delimiter")
    private String delimiter = ";";

    @JsonProperty("encryptor")
    private Encryptor encryptor = NONE;

    /**
     * Types of Jasypt PasswordEncryptors this PeerConfiguration supports
     */
    public enum Encryptor {
        NONE,
        BASIC,
        STRONG;

        public PasswordEncryptor getPasswordEncryptor() {
            switch (this) {
                case NONE: return null;
                case BASIC: return new BasicPasswordEncryptor();
                case STRONG: return new StrongPasswordEncryptor();
                default: throw new IllegalStateException("No support for encryptor type " + this);
            }
        }
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getCredentialFile() {
        return credentialFile;
    }

    public void setCredentialFile(String credentialFile) {
        this.credentialFile = credentialFile;
    }

    public CaffeineSpec getCaffeineSpec() {
        return caffeineSpec;
    }

    public void setCaffeineSpec(CaffeineSpec caffeineSpec) {
        this.caffeineSpec = caffeineSpec;
    }

    public String getUsers() {
        return users;
    }

    public void setUsers(String users) {
        this.users = users;
    }

    public String getPasswords() {
        return passwords;
    }

    public void setPasswords(String passwords) {
        this.passwords = passwords;
    }

    public String getDelimiter() {
        return delimiter;
    }

    public void setDelimiter(String delimiter) {
        this.delimiter = delimiter;
    }

    public Encryptor getEncryptor() {
        return encryptor;
    }

    public void setEncryptor(Encryptor encryptor) {
        this.encryptor = encryptor;
    }

    public Authenticator<BasicCredentials, Peer> createAuthenticator() {
        PasswordEncryptor passwordEncryptor = encryptor.getPasswordEncryptor();
        if (this.credentialFile != null) {
            InputStream allowedPeersResource = this.getClass().getClassLoader().getResourceAsStream(this.credentialFile);
            return new AllowedPeerAuthenticator(new FlatFilePeerDAO(allowedPeersResource), passwordEncryptor);
        } else if (this.users != null && this.passwords != null && this.delimiter != null) {
            return new AllowedPeerAuthenticator(new StringPeerDAO(this.users, this.passwords, this.delimiter), passwordEncryptor);
        } else {
            throw new IllegalStateException("Illegal call to createAuthenticator() when no valid configuration was set");
        }
    }

    public CachingAuthenticator<BasicCredentials, Peer> createCachingAuthenticator(MetricRegistry metrics) {
        Preconditions.checkNotNull(this.caffeineSpec, "Illegal call to createCachingAuthenticator() when the configuration "
                + "object's cachePolicy attribute is null");
        return new CachingAuthenticator<>(metrics, createAuthenticator(), this.caffeineSpec);
    }

    public void registerAuthenticator(Environment environment) {
        registerAuthenticator(environment, new PermitAllAuthorizer());
    }

    public void registerAuthenticator(Environment environment, Authorizer<Peer> authorizer) {
        Preconditions.checkNotNull(environment, "Illegal call to registerAuthenticator with a null Environment object");
        Authenticator<BasicCredentials, Peer> authenticator;
        if (this.caffeineSpec != null) {
            authenticator = createCachingAuthenticator(environment.metrics());
        } else {
            authenticator = createAuthenticator();
        }
        environment.jersey().register(new AuthDynamicFeature(
                new BasicCredentialAuthFilter.Builder<Peer>()
                        .setAuthenticator(authenticator)
                        .setAuthorizer(authorizer)
                        .setRealm(this.realm)
                        .buildAuthFilter()));
        environment.jersey().register(RolesAllowedDynamicFeature.class);
        environment.jersey().register(new AuthValueFactoryProvider.Binder<>(Peer.class));
    }
}