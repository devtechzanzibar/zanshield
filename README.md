# ZanShield SDK for Java

Add ZanShield multi-factor authentication to your system's login. ZanShield is the authentication service run by eGAZ (eGovernment Authority Zanzibar).

Your system checks the user's password as usual, then hands them to ZanShield for the second factor. ZanShield decides everything from there: whether the user sets up their first method or verifies an existing one, and which methods (authenticator app, security key, email, SMS) your system allows. It then sends the user back to you with a signed acknowledgement. This library builds the ticket you send and checks the acknowledgement you get back.

## Install

```xml
<dependency>
    <groupId>tz.co.devtech</groupId>
    <artifactId>zanshield-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

Gradle: `implementation("tz.co.devtech:zanshield-sdk:1.0.0")`. Requires Java 17+.

## Before you start

Your institution admin registers your system in the ZanShield administration console. You get:

- your **system code** (e.g. `PAYROLL01`) and **institution code**
- your system's **private key** (shown once; keep it on your server only, never in a browser or mobile app)
- ZanShield's **engine public key** (the admin console's "Download ZanShield public key" button)
- the **portal address**, e.g. `https://portal.zanshield.devtech.co.tz`

The **redirect URI** you register is where ZanShield sends users back to.

## Usage

```java
import tz.co.devtech.zanshield.*;

ZanShieldClient client = new ZanShieldClient(
        "PAYROLL01",
        "EGAZ",
        PemKeyReader.readPrivateKey(Files.readString(Path.of("/secure/zanshield-private.pem"))),
        PemKeyReader.readPublicKey(Files.readString(Path.of("/secure/zanshield-engine-public.pem"))));

// 1. After the user's password is correct:
String ticket = client.createTicket(
        user.getId(),
        user.getEmail(),
        user.getFullName(),   // optional (null): the portal greets the user by name
        user.getPhone());     // optional (null): without it the user can't choose SMS codes
response.sendRedirect(ZanShieldClient.portalUrl("https://portal.zanshield.devtech.co.tz", ticket, false));

// 2. At your redirect URI, ZanShield sends the user back with ?ticket=...
try {
    TicketPayload ack = client.acceptAcknowledgement(request.getParameter("ticket"));
    startSessionFor(ack.getUserId());
} catch (AcknowledgementRejectedException e) {
    // Genuine, but must not sign in: e.getReason() is NOT_AUTHENTICATED, EXPIRED or REPLAYED.
    showError(e.getAcknowledgement().getMessage());
}
```

`acceptAcknowledgement` does every check your callback needs before it starts a session. If any check fails it throws and returns nothing:

1. The ticket decrypts with your key and is signed by ZanShield. If not, it throws `ZanShieldException`, and you must never trust such a ticket.
2. `responseCode` is `9000` and `isAuthenticated` is true.
3. It's fresh: issued less than 3 minutes ago, configurable with `withMaxAcknowledgementAge(Duration)`.
4. Its `txnID` hasn't been used before, so a leaked callback URL can't be replayed into a second session.

`ZanShieldClient` is thread-safe, so create one and share it.

### "Add an MFA method" button

To let a signed-in user add another method (for example, a security key on top of their authenticator app), build the same ticket and ask for the add flow:

```java
String ticket = client.createTicket(user.getId(), user.getEmail(), user.getFullName(), user.getPhone());
response.sendRedirect(ZanShieldClient.portalUrl(PORTAL, ticket, true));
```

The user verifies with an existing method and is then taken straight to adding a new one. Users can't remove methods themselves; your institution admin does that in the administration console.

### More than one server

By default, used `txnID`s are remembered in memory, which protects a single JVM. If your application runs on several servers, implement `TxnIdStore` over something they share:

```java
client.withTxnIdStore((txnId, keepUntil) ->
        jdbc.update("insert into zanshield_used_txn (txn_id, keep_until) values (?, ?) on conflict do nothing",
                txnId, Timestamp.from(keepUntil)) == 1);
```

## Response codes

`ResponseCodes` has every code ZanShield uses. On an acknowledgement, only `ResponseCodes.SUCCESS` (9000) means the user verified.

## Upgrading from 1.x

- The Maven coordinates changed to `tz.co.devtech:zanshield-sdk`, and the package to `tz.co.devtech.zanshield`: replace `import tz.go.egaz.zanshield.sdk.*` with `import tz.co.devtech.zanshield.*`.
- `RequestType` is gone. ZanShield now decides whether the user registers or verifies. Use `createTicket(userId, email, fullName, mobile)`.
- For an "add a method" button, use `portalUrl(..., true)` instead of a `REGISTRATION` ticket.
- Replace your own `openAcknowledgement` checks with `acceptAcknowledgement`.

## License

Apache-2.0
