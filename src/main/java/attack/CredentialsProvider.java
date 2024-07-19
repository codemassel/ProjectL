package attack;

import java.util.HashMap;
import java.util.Map;

public class CredentialsProvider {

    private final Map<String, String> credentialsMap = new HashMap<>();

    public CredentialsProvider() {
        initializeCredentials();
    }

    private void initializeCredentials() {

        for(CredentialsEnum credential : CredentialsEnum.values()) {
            credentialsMap.put(credential.getUsername(), credential.getPassword());
        }
    }
    public Map<String, String> getCredentialsMap() {
        return credentialsMap;
    }

    private enum CredentialsEnum {
        USER1("root", "root"),
        USER2("root", "admin"),
        USER3("root", "xc3511"),
        USER4("root", "vizxv"),
        USER5("root", "admin"),
        USER6("admin", "admin"),
        USER7("root", "888888"),
        USER8("root", "xmhdipc"),
        USER9("root", "default"),
        USER10("root", "juantech"),
        USER11("root", "123456"),
        USER12("root", "54321"),
        USER13("support", "support"),
        USER14("root", "(none)"),
        USER15("admin", "password"),
        USER16("root", "root"),
        USER17("root", "12345"),
        USER18("user", "user"),
        USER19("admin", "(none)"),
        USER20("root", "pass"),
        USER21("admin", "admin1234"),
        USER22("root", "1111"),
        USER23("admin", "smcadmin"),
        USER24("admin", "1111"),
        USER25("root", "666666"),
        USER26("root", "password"),
        USER27("root", "1234"),
        USER28("root", "klv123"),
        USER29("Administrator", "admin"),
        USER30("service", "service"),
        USER31("supervisor", "supervisor"),
        USER32("guest", "guest"),
        USER33("guest", "12345"),
        USER34("guest", "12345"),
        USER35("admin1", "password"),
        USER36("administrator", "1234"),
        USER37("666666", "666666"),
        USER38("888888", "888888"),
        USER39("ubnt", "ubnt"),
        USER40("root", "klv1234"),
        USER41("root", "Zte521"),
        USER42("root", "hi3518"),
        USER43("root", "jvbzd"),
        USER44("root", "anko"),
        USER45("root", "zlxx."),
        USER46("root", "7ujMko0vizxv"),
        USER47("root", "7ujMko0admin"),
        USER48("root", "system"),
        USER49("root", "ikwb"),
        USER50("root", "dreambox"),
        USER51("root", "user"),
        USER52("root", "realtek"),
        USER53("root", "00000000"),
        USER54("admin", "1111111"),
        USER55("admin", "1234"),
        USER56("admin", "12345"),
        USER57("admin", "54321"),
        USER58("admin", "123456"),
        USER59("admin", "7ujMko0admin"),
        USER60("admin", "1234"),
        USER61("admin", "pass"),
        USER62("admin", "meinsm"),
        USER63("tech", "tech"),
        USER64("mother", "fucker");

        private final String username;
        private final String password;

        CredentialsEnum(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String getUsername() {
            return username;
        }

        public String getPassword() {
            return password;
        }
    }
}
