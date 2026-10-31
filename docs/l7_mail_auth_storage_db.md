# Layer 7 Mail, Directory Auth, Storage, Caches & Databases Reference

This guide covers **11 enterprise email, Active Directory authentication, network file storage, key-value caching, and SQL database wire protocols** across IPv4 and IPv6. *(For `MQTT`, `COAP`, and `AMQP`, see [`l7_web_and_cloud.md`](l7_web_and_cloud.md).)*

---

## 1. Electronic Mail Suite (`SMTP`, `IMAP`, `POP3`)

| Protocol | Default Port | Modifiers & Syntax Notes |
| :--- | :--- | :--- |
| **`SMTP`** | TCP `25` / `587` | `EHLO "<domain>"`, `HELO "<domain>"`, `MAIL_FROM` + `PARAM "<addr>"`, `RCPT_TO` + `PARAM "<addr>"` *(`MAIL_FROM` and `RCPT_TO` are 0-arg flags; pass the email address via `PARAM`)*, `QUIT`, `CODE <u16>`, `REPLY "<text>"`, `BODY "<mime_msg>"` |
| **`IMAP`** | TCP `143` / `993` | `TAG "<A001>"`, `CMD "<LOGIN\|SELECT\|FETCH\|LOGOUT>"`, `ARG "<args>"`, `STATUS "<OK\|NO\|BAD>"`, `RESPONSE "<str>"` (or `PAYLOAD "<line>"`) |
| **`POP3`** | TCP `110` / `995` | `CMD "<USER\|PASS\|STAT\|LIST\|RETR\|QUIT>"`, `ARG "<arg>"`, `OK`, `ERR`, `RESPONSE "<str>"` (or `PAYLOAD "<line>"`) |

```frameassembly
host mail_client { ip 10.30.1.50 }
host mail_server { ip 10.30.1.10 }

flow mail_submission_and_retrieval(mua, mta) {
    mua <- mta smtp code 220 reply "mx01.corp.example.com ESMTP Postfix" wait 1ms
    mua -> mta smtp ehlo "ws01.corp.example.com" wait 1ms
    mua <- mta smtp code 250 reply "PIPELINING STARTTLS" wait 1ms
    mua -> mta smtp mail_from param "alice@corp.example.com" wait 1ms
    mua <- mta smtp code 250 reply "2.1.0 Ok" wait 1ms
    mua -> mta smtp rcpt_to param "bob@corp.example.com" wait 1ms
    mua <- mta smtp code 250 reply "2.1.5 Ok" wait 1ms
    mua -> mta smtp body "Subject: Maintenance Window\r\n\r\nCore switch upgrade at 22:00." wait 2ms
    mua <- mta smtp code 250 reply "2.0.0 Queued" wait 1ms
    mua -> mta smtp quit wait 2ms

    mua -> mta imap tag "A001" cmd "LOGIN" arg "bob@corp.example.com SecretPass!" wait 1ms
    mua <- mta imap tag "A001" payload "A001 OK LOGIN completed" wait 1ms
    mua -> mta pop3 cmd "STAT" wait 1ms
    mua <- mta pop3 ok payload "4 18420"
}

compile {
    mail_submission_and_retrieval(mail_client, mail_server)
}
```

---

## 2. Enterprise Identity & Directory (`KERBEROS` & `LDAP`)

| Protocol | Default Port | Modifiers & Wire Encoding |
| :--- | :--- | :--- |
| **`KERBEROS`**| UDP / TCP `88` | ASN.1 DER Kerberos v5: `AS_REQ`, `AS_REP`, `TGS_REQ`, `TGS_REP`, `KRB_ERROR`, `REALM "<REALM>"`, `CNAME "<principal>"`, `SNAME "<service>"`, `ETYPE <u32>` (`18`=AES256, `17`=AES128, `23`=RC4) |
| **`LDAP`** | TCP `389` / `636`| ASN.1 BER LDAPv3: `BIND_REQ`, `BIND_RES`, `SEARCH_REQ` (encodes all 8 mandatory RFC 4511 fields), `SEARCH_ENTRY`, `SEARCH_DONE`, `UNBIND_REQ`, `MSGID <u32>`, `BASE_DN "<dn>"` *(never write `DN`)*, `FILTER "<filter>"`, `RESULT_CODE <u32>` (`0`=success, `49`=invalidCredentials) |

```frameassembly
host ad_workstation { ip 10.45.1.100 }
host domain_ctrl    { ip 10.45.1.10 }

flow active_directory_logon(ws, dc) {
    ws -> dc kerberos as_req realm "CORP.EXAMPLE.COM" cname "jdoe" sname "krbtgt/CORP.EXAMPLE.COM" etype 18 wait 1ms
    ws <- dc kerberos as_rep realm "CORP.EXAMPLE.COM" cname "jdoe" sname "krbtgt/CORP.EXAMPLE.COM" etype 18 wait 1ms
    ws -> dc kerberos tgs_req realm "CORP.EXAMPLE.COM" cname "jdoe" sname "ldap/dc01.corp.example.com" etype 18 wait 1ms
    ws <- dc kerberos tgs_rep realm "CORP.EXAMPLE.COM" cname "jdoe" sname "ldap/dc01.corp.example.com" etype 18 wait 2ms

    ws -> dc ldap bind_req msgid 1 base_dn "cn=jdoe,ou=Users,dc=corp,dc=example,dc=com" wait 1ms
    ws <- dc ldap bind_res msgid 1 result_code 0 wait 1ms
    ws -> dc ldap search_req msgid 2 base_dn "ou=Users,dc=corp,dc=example,dc=com" filter "(&(objectClass=user)(sAMAccountName=jdoe))" wait 1ms
    ws <- dc ldap search_entry msgid 2 base_dn "cn=jdoe,ou=Users,dc=corp,dc=example,dc=com" payload "memberOf: cn=NetOps,ou=Groups,dc=corp,dc=example,dc=com" wait 1ms
    ws <- dc ldap search_done msgid 2 result_code 0 wait 1ms
    ws -> dc ldap unbind_req msgid 3
}

compile {
    active_directory_logon(ad_workstation, domain_ctrl)
}
```

---

## 3. Network File Storage (`SMB` & `NFS`)

| Protocol | Default Port | Modifiers & Wire Encoding |
| :--- | :--- | :--- |
| **`SMB`** | TCP `445` | 4B NetBIOS + 64B `\xfeSMB` SMB2/3 header + UTF-16LE paths: `COMMAND "<NEGOTIATE\|SESSION_SETUP\|TREE_CONNECT\|CREATE\|READ\|WRITE\|CLOSE\|TREE_DISCONNECT\|LOGOFF>"`, `STATUS <u32>` (`0`=SUCCESS, `0xC0000022`=ACCESS_DENIED), `SESSION_ID <u64>`, `TREE_ID <u32>`, `MSGID <u64>`, `SHARE "<\\\\srv\\share>"`, `FILENAME "<file>"` |
| **`NFS`** | TCP / UDP `2049` | ONC-RPC v2 + 4B XDR padding: `VERS <3\|4>` (`4` default), `PROC "<NULL\|COMPOUND\|LOOKUP\|READ\|WRITE>"`, `TAG "<tag>"`, `PATH "</export/path>"` |

```frameassembly
host compute_node { ip 10.90.1.25 }
host nas_filer    { ip 10.90.1.10 }

flow nas_file_operations(node, filer) {
    node -> filer smb command "NEGOTIATE" msgid 0 wait 1ms
    node <- filer smb command "NEGOTIATE" status 0 msgid 0 wait 1ms
    node -> filer smb command "SESSION_SETUP" session_id 0x100001 msgid 1 wait 1ms
    node <- filer smb command "SESSION_SETUP" status 0 session_id 0x100001 msgid 1 wait 1ms
    node -> filer smb command "TREE_CONNECT" session_id 0x100001 msgid 2 share "\\\\nas01.corp\\vmstore" wait 1ms
    node <- filer smb command "TREE_CONNECT" status 0 session_id 0x100001 tree_id 10 msgid 2 wait 1ms
    node -> filer smb command "CREATE" session_id 0x100001 tree_id 10 msgid 3 filename "disk0.vhdx" wait 2ms

    node -> filer nfs vers 4 proc "COMPOUND" tag "open_read" path "/exports/hpc/checkpoint.dat" wait 1ms
    node <- filer nfs vers 4 proc "COMPOUND" tag "open_read" path "/exports/hpc/checkpoint.dat" payload "NFS4_DATA_4096B"
}

compile {
    nas_file_operations(compute_node, nas_filer)
}
```

---

## 4. In-Memory Caches & SQL Databases (`REDIS`, `MEMCACHED`, `MYSQL`, `POSTGRES`)

| Protocol | Default Port | Modifiers |
| :--- | :--- | :--- |
| **`REDIS`** | TCP `6379` | RESP2/3 arrays & replies: `CMD "<PING\|GET\|SET\|HSET\|EVAL>"`, `ARGS "<space_sep_args>"`, `REPLY_TYPE "<SIMPLE\|BULK\|INTEGER\|ARRAY\|ERROR>"`, `VALUE "<val>"` |
| **`MEMCACHED`**| TCP / UDP `11211`| Text (`set`/`get`/`STORED`) or Binary (`0x80` via `OPCODE`): `CMD "<cmd>"`, `KEY "<key>"`, `EXPTIME <u32>`, `OPCODE <u8>`, `OPAQUE <u32>`, `CAS <u64>`, `PAYLOAD "<val>"` |
| **`MYSQL`** | TCP `3306` | MySQL v10 3B-LE length framing: `GREETING`, `SERVER_VERSION "<ver>"`, `LOGIN`, `USER "<user>"`, `DB "<schema>"`, `SQL "<query>"`, `OK`, `ERR`, `ERRCODE <u16>`, `EOF` |
| **`POSTGRES`** | TCP `5432` | PostgreSQL v3.0 wire protocol: `STARTUP`, `USER "<role>"`, `DB "<dbname>"`, `AUTH_OK`, `SQL "<query>"`, `COMMAND_COMPLETE`, `READY_FOR_QUERY`, `ERROR_RESPONSE` |

```frameassembly
host app_worker   { ip 10.110.1.50 }
host data_cluster { ip 10.110.1.10 }

flow cache_and_database_tier(app, db) {
    app -> db redis cmd "SET" args "session:4201 active EX 300" wait 1ms
    app <- db redis reply_type "SIMPLE" payload "+OK\r\n" wait 1ms
    app -> db memcached cmd "set" key "ratelimit:198.51.100.9" exptime 60 opaque 701 cas 1001 payload "14" wait 1ms
    app <- db memcached cmd "STORED" key "ratelimit:198.51.100.9" opaque 701 cas 1002 wait 2ms

    app <- db mysql greeting server_version "8.4.2-Enterprise" wait 1ms
    app -> db mysql login user "orders_svc" db "commerce" wait 1ms
    app <- db mysql ok wait 1ms
    app -> db mysql sql "INSERT INTO orders (id, total_cents) VALUES (9001, 14999);" wait 1ms
    app <- db mysql err errcode 1062 payload "Duplicate entry '9001' for key 'PRIMARY'" wait 2ms

    app -> db postgres startup user "ledger_svc" db "ledger" wait 1ms
    app <- db postgres auth_ok ready_for_query wait 1ms
    app -> db postgres sql "BEGIN; UPDATE accounts SET balance = balance - 14999 WHERE id = 42; COMMIT;" wait 1ms
    app <- db postgres command_complete ready_for_query payload "COMMIT"
}

compile {
    cache_and_database_tier(app_worker, data_cluster)
}
```